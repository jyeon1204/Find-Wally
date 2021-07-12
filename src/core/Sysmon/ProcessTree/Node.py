
class Node():
    def __init__(self, id, parent, children):
        self._id = id
        self._parent = parent  # type: Node
        self._children = children
    def get_process(self, analyzer):
        """
        @rtype: Process
        """
        return analyzer.get_process(self._id)

    def get_children(self):
        """
        @rtype: list of Node
        """
        return self._children

    def get_parent(self):
        """
        @rtype: Node
        """
        return self._parent
    
    def get_action(self,analyzer):
        return analyzer.get_action(self._id)

def get_children_nodes(analyzer, node):
    # TODO: still need this hacky check?
    if isinstance(node, int):
        n = Node(node, None, [])
        p = n.get_process(analyzer)
        n.parent = p.parent
    else:
        n = node
        p = node.get_process(analyzer)
    return [Node(c, n, get_children_nodes(analyzer, c)) for c in p.children]