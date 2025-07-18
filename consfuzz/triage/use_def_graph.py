"""
File: Implementation of the Use-Def Graph, used for nicer printing (and potentially graph analysis).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Dict, Optional
from enum import Enum

from .regs import REGS
from .shared_types import *

#---------------------------------------------------------------------------------------------------
# Node and Edge Types
#---------------------------------------------------------------------------------------------------

class UseDefEdge:
    """
    Edge between an instruction and all of its users (i.e. instructions that use either a
    register value or a memory location defined by this instruction).
    """
    dst: TraceLineNum
    use: Use

    def __init__(self, dst: TraceLineNum, use: Use) -> None:
        self.dst = dst
        self.use = use

    def label(self) -> str:
        return hex(self.use.addr) if self.use.use_type == UseType.MEM else REGS[self.use.addr]


class UseDefNode:
    """
    Node representing an instruction in the trace.
    """
    line: TraceLineNum
    trimmed: bool

    def __init__(self, line: TraceLineNum):
        self.line = line
        self.trimmed = False

    def name(self) -> str:
        if self.line > 0:
            return f"node_{self.line}"
        else:
            return f"terminator_{self.line * -1}"

class TerminatorNodeType(Enum):
    """
    Final nodes of the reverse use-def graph.
    """
    DECLASSIFIED = 0
    FIRST_USE = 1
    TRIMMED_BY_DIFF = 2
    NO_FOLLOW = 3
    KNOWN_SYMBOL = 4
    KEY = 5

class TerminatorNode(UseDefNode):
    """
    Node representing the end of a branch of the use-def chain.
    """
    _type: TerminatorNodeType

    def __init__(self, _type: TerminatorNodeType, line: TraceLineNum):
        super().__init__(line)
        self._type = _type

#---------------------------------------------------------------------------------------------------
# Graph Implementation
#---------------------------------------------------------------------------------------------------

class UseDefGraph:
    nodes: Dict[TraceLineNum, UseDefNode]
    edges: Dict[TraceLineNum, list[UseDefEdge]]
    _terminator_idx: int
    head: TraceLineNum

    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self._terminator_idx = -1
        self.head = None

    #-----------------------------------------------------------------------------------------------
    # Graph Constructions
    #-----------------------------------------------------------------------------------------------

    def get_or_create(self, line: TraceLineNum) -> UseDefNode:
        """
        Get the node corresponding to a trace line, or create if it does not exist.
        """
        if line not in self.nodes.keys():
            self.nodes[line] = UseDefNode(line)
        if self.head is None:
            self.head = line
        return self.nodes[line]

    def add_terminator(self, terminator_type: TerminatorNodeType) -> TraceLineNum:
        """
        Create a terminator node and return its unique id.
        """
        node = TerminatorNode(terminator_type, self._terminator_idx)
        # NOTE: This is a bit of a hack: to identify nodes in the dictionary,
        # we typically use the line number, but for terminators we might not
        # have an associated line. We use unique negative numbers for that.
        self.nodes[self._terminator_idx] = node
        self._terminator_idx -= 1
        return node.line

    def link(self, src: TraceLineNum, dst: TraceLineNum, use: Use):
        if src not in self.edges.keys():
            self.edges[src] = []
        self.edges[src].append(UseDefEdge(dst, use))

    def trim(self, node_id: TraceLineNum) -> None:
        if node_id not in self.nodes.keys():
            self.nodes[node_id] = UseDefNode(node_id)
        self.nodes[node_id].trimmed = True

    #-----------------------------------------------------------------------------------------------
    # Graph Printing
    #-----------------------------------------------------------------------------------------------

    def print_recursive(self, node=None, prefix=""):
        if node is None:
            node = self.nodes[self.head]

        print(prefix + str(node.line))
        prefix += "    "

        if node.trimmed:
            print(prefix + " Trimmed")
            return
        if node.line not in self.edges.keys():
            print(prefix + " END!")
            return

        for e in self.edges[node.line]:
            use_str = hex(e.use.addr) if e.use.use_type == UseType.MEM else REGS[e.use.addr]
            print(prefix + "Use of " + use_str)

            self.print_recursive(self.nodes[e.dst], prefix + "    ")

    def _draw_recursive(self, node: UseDefNode, parent:UseDefNode, edge: UseDefEdge, dot_file, visited):
        node_name = node.name()
        is_terminator = isinstance(node, TerminatorNode) or (node.line not in self.edges.keys())
        already_visited = node.line in visited

        if node.trimmed:
            return
        if isinstance(node, TerminatorNode) and node._type in [TerminatorNodeType.NO_FOLLOW]:
            return

        if not already_visited:
            # Draw node
            dot_file.write(node_name)
            if is_terminator:
                dot_file.write(f" [shape=\"rectangle\"")
                if isinstance(node, TerminatorNode):
                    dot_file.write(f",label=\"{node._type.name}\"")
                    if node._type == TerminatorNodeType.DECLASSIFIED:
                        dot_file.write(",style=\"filled\",fillcolor=\"orange\"")
                    if node._type == TerminatorNodeType.KNOWN_SYMBOL:
                        dot_file.write(",style=\"filled\",fillcolor=\"yellow\"")
                    if node._type == TerminatorNodeType.FIRST_USE:
                        dot_file.write(",style=\"filled\",fillcolor=\"cyan\"")
                    if node._type == TerminatorNodeType.KEY:
                        dot_file.write(",style=\"filled\",fillcolor=\"red\"")
                dot_file.write(f"]")
            dot_file.write("\n")
            visited.add(node.line)

        # Draw edge
        if parent is not None:
            parent_name = parent.name()
            dot_file.write(f"{node_name} -> {parent_name} [label=\"{edge.label()}\"]\n")

        if is_terminator:
            return
        if already_visited:
            return

        # Visit children
        for e in self.edges[node.line]:
            self._draw_recursive(self.nodes[e.dst], parent=node, edge=e, dot_file=dot_file, visited=visited)

    def draw(self, dot_file: str) -> None:
        init = self.nodes[self.head]
        f = open(dot_file, "w")
        f.write("digraph \"usedef\" {\n")
        self._draw_recursive(init, parent=None, edge=None, dot_file=f, visited=set())
        f.write("\n}")
        f.close()
