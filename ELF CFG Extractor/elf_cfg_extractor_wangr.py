import angr
import networkx as nx

from pathlib import Path

def save_nxgraph_to_dot(graph: nx.DiGraph, dot_output_path: Path) -> tuple[bool, Path | None]:
    print(f"save_nxgraph_to_dot() Received type: {type(graph).__name__}")
    try:
        nx.drawing.nx_agraph.write_dot(graph, dot_output_path)
        return True, dot_output_path
    except Exception:
        raise RuntimeError("DOT export requires pydot or pygraphviz.")

def build_cfg(binary_input_path : Path, auto_load_libs=False) -> tuple[angr.Project | angr.analyses.cfg.cfg_fast.CFGFast ] :
    project = angr.Project(binary_input_path, auto_load_libs=auto_load_libs)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True )
    return project, cfg

def elf_to_cfg(binary_path : Path) -> nx.DiGraph:

    angr_proj, cfg = build_cfg(binary_path)

    cfg_graph = nx.DiGraph()

    for node in cfg.graph.nodes():
        block = node.block
        if block is None:
            continue

        cfg_graph.add_node(node.addr,
                           addr=node.addr,
                           size=block.size,
                           function_addr=node.function_address,
                           instr_count=len(block.capstone.insns)
                          )

    for src, dst, data in cfg.graph.edges(data=True):
        if src.block is None or dst.block is None:
            continue

        cfg_graph.add_edge(src.addr, dst.addr, jumpkind=data.get("jumpkind") )

    return cfg_graph