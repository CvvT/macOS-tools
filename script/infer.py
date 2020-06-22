#! /bin/python3

import sys
import json

from parse_log import load_model, Interface, Type, Size2Type, int2bytes, PtrType

PREFIX = "bluetooth"
SERVICE = "IOBluetoothHCIController"

# TODO: We should filter the log to reduce disk consumption as much as possible, but
# the priority is not high for now. The most important thing to do now it to detect 
# constant value and value dependece among these system calls.
# Notes: 
#  1. const value may not be constant, perhaps we do not have enough data to know it.
#  2. dependence value can be constant through out an entire log.
#  3. 

class InterfaceCall(object):
	def __init__(self, interface, group, port):
		self.interface = interface
		self.group = group
		self.port = port

	def toJson(self):
		ret = {
			"group": self.group,
			"port": self.port,
			"interface": self.interface.toJson()
		}
		return ret

	def repr(self):
		ret = "group: %d\n" % self.group
		ret += "port: %d\n" % self.port
		ret += self.interface.repr()
		return ret

	def toArgs(self):
		# Convert it data that can be later transformed into testcase by syzkaller
		ret = {
			"group": "syz_IOConnectCallMethod$%s_Group%d" % (PREFIX, self.group),
		}
		interface = self.interface.toJson()
		# kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, 
		# uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, 
		# void *outputStruct, size_t *outputStructCnt);
		args = []
		args.append(self.port)
		args.append(interface["selector"])
		args.append(0)  # Null Pointer
		args.append(0)  # 0 size
		args.append(interface["inputStruct"])
		args.append(interface["inputStructSize"])
		args.append(0)  # Null Pointer
		args.append(PtrType({"type": "ptr", "ref": {"type": "buffer", "offset": 0, "data": [0, 0, 0, 0]}}, 0).toJson())
		if interface["outputStructSize"] > 0:
			args.append(PtrType({"type": "ptr", "ref": interface["outputStruct"]}, 0).toJson())
		else:
			args.append(0)
		args.append(PtrType({"type": "ptr", "ref": {"type": "buffer", "offset": 0, \
			"data": int2bytes(interface["outputStructSize"], 8)}}, 0).toJson())
		ret["args"] = args
		return ret


class ResourceType(Type):
	def __init__(self, data, offset):
		super(ResourceType, self).__init__("resource", offset=offset, size=len(data))
		self.data = data

	def getData(self):
		return self.data

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.offset) + " " + str(self.size) + \
			" " + str(self.getData()) + "\n"
		return ret

class ConstType(ResourceType):
	def __init__(self, data, offset):
		super(ConstType, self).__init__(data, offset)
		self.type = "const"

class Path(object):
	def __init__(self):
		self.path = []
		self.index = -1
		self.type = None

	def append(self, val):
		self.path.append(val)

	def pop(self):
		self.path.pop()

	def match(self, path):
		if isinstance(path, list):
			if len(self.path) != len(path):
				return False
			for i in range(len(self.path)):
				if self.path[i] != path[i]:
					return False
			return True

		if self.index != path.index:
			return False
		if len(self.path) != len(path.path):
			return False
		for i in range(len(self.path)):
			if self.path[i] != path.path[i]:
				return False
		if self.type.offset != path.type.offset:
			return False
		if self.type.size != path.type.size:
			return False
		return True

	def equal(self, path):
		if not self.match(path):
			return False
		return self.type.getData() == path.type.getData()

	def getData(self):
		return self.type.getData()

	def repr(self):
		ret = "Path:\n"
		ret += "  path: " + str(self.path) + "\n"
		ret += "  index: " + str(self.index) + "\n"
		if self.type:
			ret += self.type.repr(indent=2)
		return ret

	def __hash__(self):
		return hash((str(self.path), self.index, self.type.offset, self.type.size))

	def __eq__(self, other):
		return self.match(other)

class Dependence(object):
	def __init__(self, outPath, inPath):
		self.outPath = outPath
		self.inPath = inPath

	def contained(self, dependences):
		for dependence in dependences:
			if self.match(dependence):
				return dependence
		return None

	def match(self, dependence):
		if self.outPath.match(dependence.outPath) and \
			self.inPath.match(dependence.inPath):
			return True
		return False

	def repr(self):
		return "Out " + self.outPath.repr() + "\nIn " + self.inPath.repr() + "\n"

class Context(object):
	def __init__(self):
		self.path = []
		self.arg = None
		self.ret = None

def genServiceOpen():
	print("resource %s_port[io_connect_t]" % PREFIX)
	print("syz_IOServiceOpen$%s(name ptr[in, string[\"%s\"]], port ptr[out, %s_port])" % \
		(PREFIX, SERVICE, PREFIX))

def genServiceOpenJson(port):
	args = []
	args.append(PtrType({"type": "ptr", "ref": {"type": "buffer", "data": [ord(x) for x in SERVICE]}}, 0).toJson())
	args.append(PtrType({"type": "ptr", "ref": {"type": "buffer", "offset": 0, \
			"data": int2bytes(port, 8)}}, 0).toJson())
	ret = {
		"group": "syz_IOServiceOpen$%s" % PREFIX,
		"args": args
	}
	return ret

def genServiceCloseJson(port):
	ret = {
		"group": "syz_IOServiceClose",
		"args": [port]
	}
	return ret

def generate_model(model, potential_dependences, potential_constants):
	genServiceOpen()
	types = {}
	for group, interface in model.items():
		relevant = [dep for dep in potential_dependences if dep.inPath.index == group or dep.outPath.index == group]
		constants = dict((path, values) for path, values in potential_constants.items() if path.index == group)
		interface.genModel(PREFIX, group, relevant, constants, types)

	for path, name in types.items():
		print("resource %s[%s]" % (name, Size2Type(path.type.size)))

def extractData(interface, path, dir):
	def search_path(ctx, type):
		if dir == "in" and ctx.arg == "outputStruct":
			return
		if dir == "out" and ctx.arg == "inputStruct":
			return

		if type.type == "buffer":
			if path.match(ctx.path):
				ctx.ret = type.getData()[path.type.offset:path.type.offset+path.type.size]
				return True
	ctx = Context()
	interface.visit(ctx, search_path)
	return ctx.ret

# Give a certain input, find the first input on which it depends.
def find_dependence(interfaces, index, potential_dependences):
	itfCall = interfaces[index]
	relevant = [dep for dep in potential_dependences if dep.inPath.index == itfCall.group]
	if len(relevant) == 0:
		return -1

	ret = index
	for dep in relevant:
		last = index - 1
		data = extractData(itfCall.interface, dep.inPath, "in")
		while last >= 0:
			itf = interfaces[last]
			if itf.group == dep.outPath.index:
				new_data = extractData(itf.interface, dep.outPath, "out")
				if data == new_data:
					break
			last -= 1
		if last != -1 and last < ret:
			ret = last

	return ret if ret != index else -1


def get_testcase(interfaces, start, end, potential_dependences):
	index = end
	while index >= start:
		last = find_dependence(interfaces, index, potential_dependences)
		if last != -1 and last < start:
			start = last
		index -= 1
	return start, end

def generate_testcase(all_inputs, potential_dependences):
	num = 0
	for inputs in all_inputs:
		for pid, interfaces in inputs.items():
			last = len(interfaces) - 1
			while last >= 0:
				start, end = get_testcase(interfaces, last, last, potential_dependences)
				print("find a testcase from %d to %d: %d" % (start, end, num))
				with open("sample/testcases/%d.prog" % num, "w") as f:
					port_num = interfaces[end].port
					json.dump(genServiceOpenJson(port_num), f)
					f.write("\n")
					for i in range(start, end+1):
						if interfaces[i].port != port_num:
							raise Exception("Unmatched port number")
						json.dump(interfaces[i].toArgs(), f)
						f.write("\n")
					json.dump(genServiceCloseJson(port_num), f)
				num += 1
				last = start - 1


def findBytes(big, small):
	a = ''.join([chr(x) for x in big])
	b = ''.join([chr(x) for x in small])
	return a.find(b)

def visit(model, all_inputs, func):
	for inputs in all_inputs:
		for pid, interfaces in inputs.items():
			for inter in interfaces:
				target = model[inter.group]
				func(target, inter)

def analyze(model, all_inputs):
	# Simplify the inputs first
	def simplify(model, itfCall):
		# print("Original: ")
		# print(itfCall.interface.repr())
		itfCall.interface.simplify(model)
		# print("New:")
		# print(itfCall.interface.repr())
		# print()

	visit(model, all_inputs, simplify)


	candidates = {}
	for inputs in all_inputs:
		# separetely analyze each log file
		for pid, interfaces in inputs.items():
			# separetely analyze each process
			resources = {}
			for inter in interfaces:
				target = model[inter.group]
				if inter.interface.outputStructSize != 0:
					# TODO: add resource of variable size and offset
					resource = ResourceType(inter.interface.outputStruct.getData(), 0)
					path = Path()
					path.index = inter.group
					path.type = resource
					if inter.group not in resources:
						resources[inter.group] = []
					resources[inter.group].append(path)
				if inter.interface.inputStructSize != 0:
					ctx = Context()
					dependences = []
					def search(ctx, type):
						if ctx.arg == "outputStruct":
							return
						if type.type == "buffer":
							data = type.getData()
							for group, items in resources.items():
								if group == inter.group:  # only inter-interface dependence
									continue
								for path in items:
									offset = findBytes(data, path.type.getData())
									if offset >= 0:
										new_path = Path()
										new_path.type = ResourceType(data[offset:offset+path.type.size], offset)
										new_path.path = list(ctx.path)
										new_path.index = inter.group
										new_dep = Dependence(path, new_path)
										if path.index == new_path.index:
											print(path.repr())
											print(new_path.repr())
											print(group, inter.group)
											raise Exception("identical index")
										# De-duplicate
										# if not contains(dependences, new_dep):
										if not new_dep.contained(dependences):
											dependences.append(new_dep)

					inter.interface.visit(ctx, search)
					if inter.group not in candidates:
						candidates[inter.group] = []
					candidates[inter.group].append(dependences)
					# print(inter.repr())
					# print("dependences:")
					# for dep in dependences:
					# 	print(dep[0].repr())
					# 	print(dep[1].repr())
					# 	print()

	potential_dependences = []
	for group, items in candidates.items():
		if len(items) == 0:
			continue

		hypothesis = items[0]
		values = {}
		for dep in hypothesis:
			values[dep] = set()

		for dependences in items[1:]:
			new_hypothesis = []
			for x in hypothesis:
				dep = x.contained(dependences)
				if dep:
					# double check the dependence is not a constant
					new_hypothesis.append(x)
					new_data = str(dep.outPath.getData())
					values[x].add(new_data)
			hypothesis = new_hypothesis
			# hypothesis = [x for x in hypothesis if x.contained(dependences)]
			if len(hypothesis) == 0:
				break

		# print("find %d dependences for group %d" % (len(hypothesis), group))
		for dep in hypothesis:
			if len(values[dep]) > 1:  # not constant
				potential_dependences.append(dep)
				# print(dep.repr())
				# print(values[dep])

	# print("find %d dependences" % len(potential_dependences))
	# for dep in potential_dependences:
	# 	print(dep.repr())


	# dectect constant/flag
	candidates = {}
	for inputs in all_inputs:
		# separetely analyze each log file
		for pid, interfaces in inputs.items():
			# separetely analyze each process
			for inter in interfaces:
				ctx = Context()
				# constants = []
				def search_const(ctx, type):
					if ctx.arg == "outputStruct":
						return
					if type.type == "buffer":
						if type.size == 0:
							return
						data = type.getData()
						offset = 0
						while offset < type.size:
							new_path = Path()
							new_path.type = ConstType(data[offset:offset+4], offset)
							new_path.path = list(ctx.path)
							new_path.index = inter.group
							offset += 4
							if new_path not in candidates:
								candidates[new_path] = set()
							candidates[new_path].add(int.from_bytes(new_path.type.getData(), "little"))

				inter.interface.visit(ctx, search_const)

	generate_model(model, potential_dependences, candidates)
	generate_testcase(all_inputs, potential_dependences)

def main(filepath="sample/interface_type.json"):
	model = load_model(filepath)
	for index, interface in model.items():
		print("group: %d" % index)
		print(interface.repr())

	all_inputs = []
	with open("sample/output.txt", "r") as f:
		inputs = {}
		for line in f:
			if line.startswith("--------"):
				# analyze(model, inputs)
				if len(inputs) > 0:
					all_inputs.append(inputs)
				inputs = {}
				continue
			frame = json.loads(line)
			pid = frame["pid"]
			if pid not in inputs:
				inputs[pid] = []
			interface = Interface(frame)
			inputs[pid].append(InterfaceCall(interface, frame["id"], frame["port"]))
	if len(inputs) > 0:
		all_inputs.append(inputs)
	analyze(model, all_inputs)
	return 0

if __name__ == '__main__':
	sys.exit(main())