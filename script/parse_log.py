#! /bin/python3

import json
import os
import sys
import traceback

class Type:
	def __init__(self, type, offset=0, size=0):
		self.type = type
		self.offset = offset
		self.size = size

	def type2ID(self, type):
		if type == "buffer":
			return 0
		if type == "ptr":
			return 1
		if type == "struct":
			return 2
		raise Exception("unknown type %s" % type)

	def id2Type(self, id):
		if id == 0:
			return "buffer"
		if id == 1:
			return "ptr"
		if id == 2:
			return "struct"

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.size) + "\n"
		return ret

	@staticmethod
	def construct(data, offset=0, isPtr=True):
		if "offset" in data:  # it is a pre-loaded model
			offset = data["offset"]
		type = data["type"]
		if type == "ptr" or (isPtr and "ptr" in data):
			return PtrType(data, offset)
		if type == "buffer":
			return BufferType(data, offset)
		elif type == "struct":
			return StructType(data, offset)
		raise Exception("unknown type")

	def toJson(self):
		ret = {
			"type": self.type,
			"offset": self.offset,
			"size": self.size
		}
		return ret


class PtrType(Type):
	def __init__(self, data, offset):
		super(PtrType, self).__init__("ptr", offset=offset, size=8)
		if "subtype" in data:
			self.subtype = data["subtype"]
		else:
			self.subtype = "heap"
			if "protection" in data:
				if data["protection"][2] == 'x':
					self.subtype = "code"

		if "ref" in data:
			self.ref = Type.construct(data["ref"], 0, isPtr=False)
		else:
			self.ref = Type.construct(data, 0, isPtr=False)

		if "optional" in data:
			self.optional = True
		else:
			self.optional = False

	def refine(self, other):
		if other.type == "buffer":
			return other.refine(self)
		if other.type == "struct":
			if other.size < self.size or len(other.fields) <= 1:
				raise Exception("incorrect struct type")
			other = other.fields[0]  # due to alignment, the size must be larger than 8
			return self.refine(other)
		if self.subtype != other.subtype:
			print(self.subtype, other.subtype)
			raise Exception("different subtype for pointer")
		# refine reference
		ret = self.ref.refine(other.ref)
		if ret is None:
			raise Exception("return none ref")
		self.ref = ret
		return self

	def filter(self, frame):
		if self.ref:
			frame = self.ref.filter(frame)
		return frame

	def repr(self, indent=0):
		ret = " "*indent + self.subtype + " " + self.type + " " + str(self.size)
		if self.optional:
			ret += " optional"
		ret += "\n"
		if self.ref:
			ret += self.ref.repr(indent+2)
		return ret

	def toJson(self):
		ret = super(PtrType, self).toJson()
		ret["subtype"] = self.subtype
		ret["optional"] = self.optional
		if self.ref:
			ret["ref"] = self.ref.toJson()
		return ret


class BufferType(Type):
	def __init__(self, data, offset):
		super(BufferType, self).__init__("buffer", offset=offset, size=len(data["data"]))
		self.data = data["data"]

	def refine(self, other):
		# pointer can be optional
		if other.type == "ptr":
			if self.isNull():
				return other
			# else:
			# 	print(self.data)

		if self.size > other.size:
			self.size = other.size
			self.data = self.data[:self.size]
		return self

	def isNull(self):
		if len(self.data) != 8:
			return False
		for each in self.data:
			if each != 0:
				return False
		return True

	def filter(self, frame):
		# print(frame, self.size)
		frame["data"] = frame["data"][:self.size]
		return frame

	def toJson(self):
		ret = super(BufferType, self).toJson()
		ret["data"] = self.data
		return ret


class StructType(Type):
	def __init__(self, data, offset):
		super(StructType, self).__init__("struct", offset=offset)
		self.fields = []
		for each in data["fields"]:
			struct = Type.construct(each, offset, isPtr=True)
			self.fields.append(struct)
			offset += struct.size
			self.size += struct.size

	def split(self, index, size):
		field = self.fields[index]
		if field.type != "buffer":
			raise Exception("split none buffer type")

		rest = field.data[size:]
		field.data = field.data[:size]
		field.size = len(field.data)

		if len(rest) != 0:
			new_field = BufferType({"data": rest}, field.offset+field.size)
			self.fields.insert(index+1, new_field)


	def refine(self, other):
		if other.type != "struct":
			return other.refine(self)

		fields = []
		l = r = 0
		while l < len(self.fields) and r < len(other.fields):
			ltype, rtype = self.fields[l], other.fields[r]
			if ltype.size == rtype.size:
				fields.append(ltype.refine(rtype))
			else:
				if ltype.size > rtype.size:
					self.split(l, rtype.size)
				else:
					other.split(r, ltype.size)
				continue
			l += 1
			r += 1

		self.fields = fields
		self.size = fields[-1].offset + fields[-1].size
		return self

	def filter(self, frame):
		# fast path
		# print(frame)
		if len(self.fields) == len(frame["fields"]):
			new_fields = []
			for i in range(len(self.fields)):
				new_fields.append(self.fields[i].filter(frame["fields"][i]))
			frame["fields"] = new_fields
			return frame

		return frame

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.size) + "\n"
		for each in self.fields:
			ret += each.repr(indent+2)
		return ret

	def toJson(self):
		ret = super(StructType, self).toJson()
		ret["fields"] = [each.toJson() for each in self.fields]
		return ret


class Interface:
	def __init__(self, frame):
		self.selector = frame["selector"]
		self.inputStructSize = frame["inputStructSize"]
		self.outputStructSize = frame["outputStructSize"]

		self.inputStruct = Type.construct(frame["inputStruct"])

	def refine(self, other):
		if self.selector != other.selector or \
			self.inputStructSize != other.inputStructSize or \
			self.outputStructSize != other.outputStructSize:
			print(self.repr())
			print(other.repr())
			raise Exception("unmatched interface")
		self.inputStruct.refine(other.inputStruct)

	def filter(self, frame):
		if self.inputStruct:
			frame["inputStruct"] = self.inputStruct.filter(frame["inputStruct"])
		return frame

	def repr(self):
		ret = "selector: %s\n" % self.selector
		if self.inputStruct:
			ret += "inputStruct:\n"
			ret += self.inputStruct.repr()
		return ret

	def toJson(self):
		ret = {
			"selector": self.selector,
			"inputStructSize": self.inputStructSize,
			"outputStructSize": self.outputStructSize,
			"inputStruct": self.inputStruct.toJson()
		}
		return ret


def gen_model(frames, interface=None):
	if len(frames) == 0:
		return None

	if interface is None:
		interface = Interface(frames[0])
		# print(frames[0])
		# print(interface.repr())
		# print()
		frames = frames[1:]

	for frame in frames:
		# print(frame)
		other = Interface(frame)
		# print(other.repr())
		interface.refine(other)

		# print(interface.repr())
		# print()

	return interface


def load_model(filepath):
	if not os.path.exists(filepath):
		return {}
	with open(filepath, "r") as f:
		model = json.load(f)
		interfaces = {}
		for k, v in model.items():
			interfaces[k] = Interface(v)
		return interfaces


def extract_model(frames, filepath="sample/interface_type.json"):
	print(len(frames))
	groups = {}
	for frame in frames:
		index = frame["id"]
		if index not in groups:
			groups[index] = []
		groups[index].append(frame)

	model = load_model(filepath)
	for index, frames in groups.items():
		# if index != 0:  # testing
		# 	continue

		interface = None
		if index in model:
			interface = model[index]
		interface = gen_model(frames, interface=interface)
		print("Group: %d:" % index)
		if interface:
			print(interface.repr())
			model[index] = interface
		print("\n")

	# with open(filepath, "w") as f:
	# 	json.dump(dict((k, v.toJson()) for k, v in model.items()), f)

	return model

def merge_log(kernellog, userlog):
	# Group user input by pid
	inputs = []
	with open(userlog, "r") as userf:
		frames = []
		pid = None
		for line in userf:
			try:
				ent = json.loads(line.strip())
				if "pid" in ent:
					if pid is not None:
						inputs.append((pid, frames))
						frames = []
					pid = ent["pid"]
				else:
					frames.append(ent)
			except:
				pass
		if len(frames) != 0 and pid is not None:
			inputs.append((pid, frames))

	# Group kernel input by pid
	kernel_inputs = {}
	with open(kernellog, "r") as f:
		for line in f:
			try:
				ent = json.loads(line.strip())
				pid = ent["pid"]
				if pid not in kernel_inputs:
					kernel_inputs[pid] = []
				kernel_inputs[pid].append(ent)
			except json.JSONDecodeError as e:
				pass

	# Create port mapping
	port_mapping = {}
	for pid, frames in inputs:
		port_counts = {}
		for frame in frames:
			port = frame["port"]
			if port not in port_counts:
				port_counts[port] = 0
			port_counts[port] += 1
		addr_counts = {}
		for frame in kernel_inputs[pid]:
			addr = frame["port"]
			if addr not in addr_counts:
				addr_counts[addr] = 0
			addr_counts[addr] += 1
		for port, count in port_counts.items():
			for addr, c in addr_counts.items():
				if count == c:
					port_mapping[port] = addr
					break
	print(port_mapping)

	outputs = []
	total_invalid = 0
	for pid, frames in inputs:
		print("pid: %d, frames: %d" % (pid, len(frames)))
		if pid not in kernel_inputs:
			continue
		kernel_frames = kernel_inputs[pid]
		cur_frame = 0
		for frame in frames:
			port = frame["port"]
			if port not in port_mapping:
				continue
			port_addr = port_mapping[port]
			while cur_frame < len(kernel_frames):
				ent = kernel_frames[cur_frame]
				if ent["port"] != port_addr:
					cur_frame += 1
					continue

				if ent["selector"] != frame["selector"]:
					raise Exception("unmatched selector")
				if ent["outputStructCnt"] != frame["outputStructSize"]:
					raise Exception("unmatched outputStructCnt")
				if ent["inputStructCnt"] != frame["inputStructSize"]:
					raise Exception("unmatched inputStructCnt")

				frame["pid"] = pid
				frame["id"] = ent["id"]
				frame["port_addr"] = ent["port"]
				if (int(frame["ret"], 16) >> 26 == 0) and ent["id"] != -1:
					outputs.append(frame)
				else:
					# print(frame["ret"], ent["id"])
					total_invalid += 1
					print("invalid frame: ", frame)
				cur_frame += 1
				break

	return outputs, total_invalid

def main(kernellog, userlog):
	if not os.path.exists(kernellog) or \
		not os.path.exists(userlog):
		print("file does not exist")
		return

	# merge two logs obtained from user-space hooking and kernel-space hooking.
	# one-to-one mapping, elimnate noise from other process.
	frames, invalid = merge_log(kernellog, userlog)
	print("total invalid frames: %d" % invalid)
	model = extract_model(frames)
	# filtered_frames = []
	# for frame in frames:
	# 	index = frame["id"]
	# 	interface = model[index]
	# 	frame = interface.filter(frame)
	# 	filtered_frames.append(frame)
	# with open("sample/output.txt", "w") as f:
	# 	for frame in filtered_frames:
	# 		f.write(json.dumps(frame))
	# 		f.write("\n")

def fix(kernellog):
	with open(kernellog, "r") as inputf, open("sample/output.txt", "w") as outputf:
		for line in inputf:
			outputf.write(line.strip()+"}\n")

def count(kernellog):
	num = 0
	with open(kernellog, "r") as inputf:
		for line in inputf:
			item = json.loads(line)
			if item["pid"] == 142:
				num += 1
	print(num)

if __name__ == '__main__':
	# fix("sample/kernel_hook.txt")
	# main("sample/kernel_hook.txt", "sample/user_hook.txt")
	if len(sys.argv) != 3:
		sys.exit(1)
	# count(sys.argv[1])
	main(sys.argv[1], sys.argv[2])

