import r2pipe
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

def elf_to_cfg(binary_path: Path) -> nx.DiGraph:
    r2 = r2pipe.open(str(binary_path), flags=["-2"])
    
    r2.cmd("aaa")

    functions = r2.cmdj("aflj")
    G = nx.DiGraph()

    for f in functions:
        faddr = f["offset"]
        fname = f["name"]

        r2.cmd(f"s {faddr}")
        blocks = r2.cmdj("afbj")
        if not blocks:
            continue

        for b in blocks:
            baddr = b["addr"]

            # Add basic block node
            G.add_node(baddr,
                       function=faddr,
                       function_name=fname,
                       size=b["size"]
                       )

            # Jump edge
            if b.get("jump", -1) != -1:
                G.add_edge(baddr,
                           b["jump"],
                           type="jump"
                           )

            # Fail edge (conditional fall-through)
            if b.get("fail", -1) != -1:
                G.add_edge(baddr,
                           b["fail"],
                           type="fail"
                           )

    r2.quit()
    return G