// Graph layer — petgraph in-memory, edges persisted to SurrealKV (M-04)
// Edges stored as graph:edge:<from>:<kind>:<to> keys

pub mod edges;
pub mod graph;
pub use edges::{Edge, EdgeKind};
pub use graph::Graph;
