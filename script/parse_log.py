#! /bin/python3

import json

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
		if isPtr and "ptr" in data:
			return PtrType(data, offset)
		type = data["type"]
		if type == "buffer":
			return BufferType(data, offset)
		elif type == "struct":
			return StructType(data, offset)
		raise Exception("unknown type")


class PtrType(Type):
	def __init__(self, data, offset):
		super(PtrType, self).__init__("ptr", offset=offset, size=8)
		self.subtype = "heap"
		self.ref = None
		if "protection" in data:
			if data["protection"][2] != 'x':
				self.subtype = "code"
		self.ref = Type.construct(data, 0, isPtr=False)

	def refine(self, other):
		# FIXME: pointer can be optional
		if other.type == "buffer":
			return other.refine(self)
		if other.type == "struct":
			if other.size < self.size or len(other.fields) <= 1:
				raise Exception("incorrect struct type")
			other = other.fields[0]  # due to alignment, the size must be larger than 8
			return self.refine(other)
		return self

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.size) + "\n"
		if self.ref:
			ret += self.ref.repr(indent+2)
		return ret

class BufferType(Type):
	def __init__(self, data, offset):
		super(BufferType, self).__init__("buffer", offset=offset, size=len(data["data"]))
		self.data = data["data"]

	def refine(self, other):
		# FIXME: pointer can be optional
		if self.size > other.size:
			self.size = other.size
			self.data = self.data[:self.size]
		return self


class StructType(Type):
	def __init__(self, data, offset):
		super(StructType, self).__init__("struct", offset=offset)
		self.fields = []
		for each in data["fields"]:
			struct = Type.construct(each, offset, isPtr=True)
			self.fields.append(struct)
			offset += struct.size
			self.size += struct.size

	def refine(self, other):
		if other.type != "struct":
			return other.refine(self)
		# fast path
		if len(self.fields) == len(other.fields):
			align = True
			for i in range(len(self.fields)):
				if self.fields[i].offset != other.fields[i].offset:
					align = False
					break
			if align:
				fields = []
				for i in range(len(self.fields)):
					fields.append(self.fields[i].refine(other.fields[i]))
				self.fields = fields
				return self

		# slow path
		raise Exception("not implemented yet")

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.size) + "\n"
		for each in self.fields:
			ret += each.repr(indent+2)
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

	def repr(self):
		ret = "selector: %s\n" % self.selector
		if self.inputStruct:
			ret += "inputStruct:\n"
			ret += self.inputStruct.repr()
		return ret


def gen_model(frames):
	if len(frames) == 0:
		return None

	interface = Interface(frames[0])
	for frame in frames[1:]:
		other = Interface(frame)
		interface.refine(other)
	return interface


def extract_model(frames):
	print(len(frames))
	groups = {}
	for frame in frames:
		index = frame["id"]
		if index not in groups:
			groups[index] = []
		groups[index].append(frame)

	for index, frames in groups.items():
		model = gen_model(frames)
		print("Group: %d:" % index)
		if model:
			print(model.repr())
		print("\n")

def merge_log(kernellog, userlog):
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

	outputs = []
	with open(kernellog, "r") as f:
		for pid, frames in inputs:
			print("pid: %d, frames: %d" % (pid, len(frames)))
			for frame in frames:
				while True:
					line = f.readline()
					if not line:
						return outputs

					try:
						ent = json.loads(line.strip())
						if ent["pid"] != pid:
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
						if frame["ret"] == "0x0" and ent["id"] != -1:
							outputs.append(frame)
						else:
							# print(frame["ret"], ent["id"])
							print("invalid frame: ", frame)
						break
					except json.JSONDecodeError:
						pass
					except Exception as e:
						print(frame)
						print(ent)
						raise e

	return outputs

def main(kernellog, userlog):
	# merge two logs obtained from user-space hooking and kernel-space hooking.
	# one-to-one mapping, elimnate noise from other process.
	frames = merge_log(kernellog, userlog)
	extract_model(frames)
	# with open("sample/output.txt", "w") as f:
	# 	for frame in frames:
	# 		f.write(json.dumps(frame))
	# 		f.write("\n")

if __name__ == '__main__':
	main("sample/kernel_hook.txt", "sample/user_hook.txt")
