import angr
import networkx as nx

from pathlib import Path

def save_nxgraph_to_dot(graph: nx.DiGraph, dot_output_path: Path) -> tuple[bool, Path | None]:
    print(f"save_nxgraph_to_dot function's received type: {type(graph).__name__}")
    try:
        nx.drawing.nx_agraph.write_dot(graph, dot_output_path)
        print(f"Successfully converted nx.DiGraph to .dot type: '{dot_output_path}'")
        return True, dot_output_path
    except Exception as e:
        #raise RuntimeError("DOT export requires pydot or pygraphviz.")
        print(f"An error occurred during dot conversion: {e}")
        return False, None

def save_nxgraph_to_graphml(graph_object, graphml_output_path: Path) -> tuple[bool, Path | None]:
    print(f"save_nxgraph_to_graphml function's received type: {type(graph_object).__name__}")
    
    if not isinstance(graph_object, (nx.Graph, nx.DiGraph, nx.MultiGraph, nx.MultiDiGraph)):
        print(f"Conversion Failed: The input object is not a valid NetworkX Graph.")
        print(f"Please convert your data to an nx.Graph object first.")
        return False, None

    try:
        nx.write_graphml(graph_object, str(graphml_output_path))
        print(f"Successfully converted nx.DiGraph to .graphml type: '{graphml_output_path}'")
        return True, graphml_output_path
    except Exception as e:
        # This catches errors that occur *during* writing, but 
        # the input check above should prevent the 'is_directed' error.
        print(f"An error occurred during GraphML conversion: {e}")
        return False, None

def build_cfg(binary_input_path : Path, auto_load_libs=False) -> tuple[angr.Project | angr.analyses.cfg.cfg_fast.CFGFast ] :
    project = angr.Project(binary_input_path, auto_load_libs=auto_load_libs)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True )
    return project, cfg

def elf_to_cfg(binary_path : Path) -> nx.DiGraph | None:
    angr_proj, cfg = build_cfg(binary_path)
    cfg_graph = nx.DiGraph()

    for node in cfg.graph.nodes():
        block = node.block
        if block is None:
            continue

        func = cfg.kb.functions.get(node.function_address, None)
        func_name = func.name if func else "UNKNOWN"

        cfg_graph.add_node(node.addr,
                           addr=node.addr,
                           size=block.size,
                           instr_count=len(block.capstone.insns),
                           function_name=func_name,
                           function_addr=node.function_address)

    for src, dst, data in cfg.graph.edges(data=True):
        if src.block is None or dst.block is None:
            continue
        cfg_graph.add_edge(src.addr, dst.addr, jumpkind=data.get("jumpkind") )

    return cfg_graph