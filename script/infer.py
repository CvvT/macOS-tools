#! /bin/python3

import sys
import json

from parse_log import load_model, Interface, Type

PREFIX = "bluetooth"
SERVICE = "IOBluetoothHCIController"

class Syscall(object):
	def __init__(self):
		pass

# TODO: We should filter the log to reduce disk consumption as much as possible, but
# the priority is not high for now. The most important thing to do now it to detect 
# constant value and value dependece among these system calls.
# Notes: 
#  1. const value may not be constant, perhaps we do not have enough data to know it.
#  2. dependence value can be constant through out an entire log.
#  3. 

class Arg(object):
	def __init__(self, name, type):
		self.name = name
		self.type = type

class ConstArg(Arg):
	def __init__(self, value):
		super(ConstArg, self).__init__("const")
		self.value = value

class PtrArg(Arg):
	def __init__(self, type):
		super(PtrArg, self).__init__("ptr")

class BufferArg(Arg):
	def __init__(self):
		super(BufferArg, self).__init__("buffer")

class StructArg(Arg):
	def __init__(self):
		super(StructArg, self).__init__("struct")

class InterfaceCall(object):
	def __init__(self, interface, group, port):
		self.interface = interface
		self.group = group
		self.port = port

	def repr(self):
		ret = "group: %d\n" % self.group
		ret += "port: %d\n" % self.port
		ret += self.interface.repr()
		return ret

class ResourceType(Type):
	def __init__(self, data, offset):
		super(ResourceType, self).__init__("resource", offset=offset, size=len(data))
		self.data = data

	def getData(self):
		return self.data

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.size) + \
			" " + str(self.getData()) + "\n"
		return ret

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

	def repr(self):
		ret = "Path:\n"
		ret += "  path: " + str(self.path) + "\n"
		ret += "  index: " + str(self.index) + "\n"
		if self.type:
			ret += self.type.repr(indent=2)
		return ret

class Context(object):
	def __init__(self):
		self.path = []
		self.arg = None

def genServiceOpen():
	print("resource %s_port[io_connect_t]" % PREFIX)
	print("syz_IOServiceOpen$%s(name ptr[in, string[\"%s\"]], port ptr[out, %s_port])" % \
		(PREFIX, SERVICE, PREFIX))

def findBytes(big, small):
	a = ''.join([chr(x) for x in big])
	b = ''.join([chr(x) for x in small])
	return a.find(b)

def contains(dependences, dep):
	for dependence in dependences:
		if dependence[0].match(dep[0]) and dependence[1].match(dep[1]):
			return True
	return False

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
										new_dep = (path, new_path)
										if path.index == new_path.index:
											print(path.repr())
											print(new_path.repr())
											print(group, inter.group)
											raise Exception("identical index")
										# De-duplicate
										if not contains(dependences, new_dep):
											dependences.append((path, new_path))

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

	for group, items in candidates.items():
		if len(items) == 0:
			continue

		hypothesis = items[0]
		# for each in hypothesis:
		# 	if each[0].index == each[1].index:
		# 		raise Exception("identical index")
		# 	print(each[0].repr())
		# 	print(each[1].repr())
		for dependences in items[1:]:
			hypothesis = [x for x in hypothesis if contains(dependences, x)]
			if len(hypothesis) == 0:
				break

		print("find %d dependences for group %d" % (len(hypothesis), group))
		for dep in hypothesis:
			print(dep[0].repr())
			print(dep[1].repr())
			print()


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