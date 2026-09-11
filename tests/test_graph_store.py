import unittest
from graphpath.topology.graph_store import GraphStore

class TestGraphStore(unittest.TestCase):
    def setUp(self):
        self.store = GraphStore()

    def tearDown(self):
        GraphStore.close_all()

    def test_node_upsert_and_retrieval(self):
        self.store.add_node("192.168.1.1", {"type": "router", "vendor": "Cisco"})
        nodes = self.store.nodes
        self.assertIn("192.168.1.1", nodes)
        self.assertEqual(nodes["192.168.1.1"]["type"], "router")
        self.assertEqual(nodes["192.168.1.1"]["vendor"], "Cisco")

    def test_edge_addition(self):
        self.store.add_node("192.168.1.1", {"type": "router"})
        self.store.add_node("192.168.1.100", {"type": "workstation"})
        self.store.add_edge("192.168.1.1", "192.168.1.100", {"layer": 3, "method": "sweep"})
        edges = self.store.edges
        self.assertTrue(len(edges) > 0)

    def test_cytoscape_export(self):
        self.store.add_node("10.0.0.1", {"type": "switch"})
        elements = self.store.export_cytoscape_elements()
        self.assertTrue(any(el["data"]["id"] == "10.0.0.1" for el in elements))

if __name__ == "__main__":
    unittest.main()