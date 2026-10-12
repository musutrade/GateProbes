#![feature(rustc_private)]
extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_index;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_driver::{Callbacks, Compilation};
use rustc_index::IndexVec;
use rustc_middle::mir::{self, coverage::*};
use rustc_middle::ty::TyCtxt;
use rustc_middle::{mono::MonoItem, ty};
use rustc_span::{def_id::LocalDefId, Span};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
const SCHEMA: &str = "rustc-mir-block-inventory/3";
const RUSTC_COMMIT: &str = "8bab26f4f68e0e26f0bb7960be334d5b520ea452";
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn owner_id(tcx: TyCtxt<'_>, id: rustc_span::def_id::DefId) -> String {
    format!("{:?}", tcx.def_path_hash(id))
}

/// Normal control-flow edges, retaining parallel switch edges. Exceptional,
/// imaginary and coroutine destruction paths are retained in the raw CFG but
/// excluded from the separately versioned normal-flow complexity rule.
fn normal_successors(kind: &mir::TerminatorKind<'_>) -> Vec<usize> {
    use mir::TerminatorKind::*;
    match kind {
        Goto { target } | Drop { target, .. } | Assert { target, .. } => vec![target.index()],
        SwitchInt { targets, .. } => targets.all_targets().iter().map(|b| b.index()).collect(),
        Call { target, .. } => target.iter().map(|b| b.index()).collect(),
        Yield { resume, .. } => vec![resume.index()],
        FalseEdge { real_target, .. } | FalseUnwind { real_target, .. } => {
            vec![real_target.index()]
        }
        InlineAsm { targets, .. } => targets.iter().map(|b| b.index()).collect(),
        Return
        | Unreachable
        | UnwindResume
        | UnwindTerminate(_)
        | CoroutineDrop
        | TailCall { .. } => vec![],
    }
}

fn eligible(tcx: TyCtxt<'_>, id: LocalDefId) -> bool {
    tcx.def_kind(id).is_fn_like()
        || matches!(
            tcx.def_kind(id),
            rustc_hir::def::DefKind::Ctor(_, rustc_hir::def::CtorKind::Fn)
        )
}

type MirProvider = for<'tcx> fn(TyCtxt<'tcx>, LocalDefId) -> &'tcx mir::Body<'tcx>;
type IdsProvider =
    for<'tcx> fn(TyCtxt<'tcx>, rustc_middle::ty::InstanceKind<'tcx>) -> Option<CoverageIdsInfo>;
static ORIGINAL_MIR: OnceLock<MirProvider> = OnceLock::new();
static ORIGINAL_CTFE: OnceLock<MirProvider> = OnceLock::new();
static ORIGINAL_IDS: OnceLock<IdsProvider> = OnceLock::new();

fn instrument(tcx: TyCtxt<'_>, id: LocalDefId) -> &mir::Body<'_> {
    if tcx.is_constructor(id.to_def_id()) {
        return tcx.mir_for_ctfe(id);
    }
    let original = ORIGINAL_MIR.get().unwrap()(tcx, id);
    inject(tcx, id, original)
}
fn ctfe(tcx: TyCtxt<'_>, id: LocalDefId) -> &mir::Body<'_> {
    let original = ORIGINAL_CTFE.get().unwrap()(tcx, id);
    if !matches!(
        tcx.def_kind(id),
        rustc_hir::def::DefKind::Ctor(_, rustc_hir::def::CtorKind::Fn)
    ) {
        return original;
    }
    inject(tcx, id, original)
}
fn inject<'tcx>(
    tcx: TyCtxt<'tcx>,
    id: LocalDefId,
    original: &mir::Body<'tcx>,
) -> &'tcx mir::Body<'tcx> {
    let mut body = original.clone();
    let mut text = String::new();
    let count = body.basic_blocks.len();
    for n in 0..count {
        text.push_str(&format!("bb{n:08}\n"));
    }
    let directory = std::path::PathBuf::from(std::env::var("NATIVE_DRIVER_OUTPUT").unwrap())
        .parent()
        .unwrap()
        .to_owned();
    let filename = directory.join(format!("owner-{}.mir-map", id.local_def_index.as_u32()));
    std::fs::write(&filename, &text).unwrap();
    let file = tcx.sess.source_map().load_file(&filename).unwrap();
    let mut mappings = vec![];
    for (bb, data) in body.basic_blocks_mut().iter_enumerated_mut() {
        data.statements
            .retain(|stmt| !matches!(stmt.kind, mir::StatementKind::Coverage(_)));
        let source_info = data.terminator().source_info;
        let bcb = BasicCoverageBlock::from_usize(bb.index());
        data.statements.insert(
            0,
            mir::Statement::new(
                source_info,
                mir::StatementKind::Coverage(CoverageKind::VirtualCounter { bcb }),
            ),
        );
        let lo = file.start_pos + rustc_span::BytePos((bb.index() * 11) as u32);
        mappings.push(Mapping {
            kind: MappingKind::Code { bcb },
            span: Span::with_root_ctxt(lo, lo + rustc_span::BytePos(10)),
        });
    }
    body.function_coverage_info = Some(Box::new(FunctionCoverageInfo {
        // This is an LLVM profile discriminator, not an artifact trust anchor.
        // The manifest separately hashes the complete serialized CFG and sources.
        function_source_hash: u64::from_le_bytes(
            Sha256::digest(format!("{}:{original:?}", owner_id(tcx, id.to_def_id())).as_bytes())
                [..8]
                .try_into()
                .unwrap(),
        ),
        node_flow_data: NodeFlowData {
            supernodes: IndexVec::new(),
            succ_supernodes: IndexVec::new(),
        },
        priority_list: (0..count).map(BasicCoverageBlock::from_usize).collect(),
        mappings,
    }));
    tcx.arena.alloc(body)
}

fn ids<'tcx>(
    tcx: TyCtxt<'tcx>,
    kind: rustc_middle::ty::InstanceKind<'tcx>,
) -> Option<CoverageIdsInfo> {
    let body = tcx.instance_mir(kind);
    let info = body.function_coverage_info.as_ref()?;
    if !info.node_flow_data.supernodes.is_empty() {
        return ORIGINAL_IDS.get().unwrap()(tcx, kind);
    }
    let mut physical = rustc_data_structures::fx::FxIndexMap::default();
    let mut terms = IndexVec::new();
    for &bcb in &info.priority_list {
        let counter = CounterId::from_usize(bcb.index());
        physical.insert(bcb, counter);
        terms.push(Some(CovTerm::Counter(counter)));
    }
    Some(CoverageIdsInfo {
        num_counters: terms.len() as u32,
        phys_counter_for_node: physical,
        term_for_bcb: terms,
        expressions: IndexVec::new(),
    })
}

fn coverage_on(tcx: TyCtxt<'_>, id: LocalDefId) -> bool {
    use rustc_hir::{attrs::CoverageAttrKind, find_attr};
    if let Some(kind) = find_attr!(tcx, id, Coverage(kind) => kind) {
        return matches!(kind, CoverageAttrKind::On);
    }
    tcx.opt_local_parent(id)
        .is_none_or(|parent| tcx.coverage_attr_on(parent))
}

fn span(tcx: TyCtxt<'_>, s: Span, depth: usize) -> Value {
    if s.is_dummy() {
        return json!({"dummy":true});
    }
    assert!(depth < 128, "expansion graph too deep");
    let sm = tcx.sess.source_map();
    let file = sm.lookup_source_file(s.lo());
    assert!(s.hi() <= file.end_position(), "span crosses source files");
    let expansion = if s.from_expansion() {
        let d = s.ctxt().outer_expn_data();
        json!({"id":format!("{:?}",s.ctxt().outer_expn()), "kind":format!("{:?}",d.kind),
            "macro_def":d.macro_def_id.map(|id|format!("{:?}",tcx.def_path_hash(id))),
            "call_site":span(tcx,d.call_site,depth+1), "def_site":span(tcx,d.def_site,depth+1)})
    } else {
        Value::Null
    };
    json!({"source_id":file.start_pos.0,"file":file.name.prefer_local_unconditionally().to_string(),"start":s.lo().0-file.start_pos.0,
        "end":s.hi().0-file.start_pos.0,"context":format!("{:?}",s.ctxt()),"expansion":expansion})
}

struct Inventory;
impl Callbacks for Inventory {
    fn config(&mut self, config: &mut rustc_interface::interface::Config) {
        config.override_queries = Some(|_, providers| {
            providers.queries.coverage_attr_on = coverage_on;
            ORIGINAL_MIR.set(providers.queries.optimized_mir).unwrap();
            ORIGINAL_CTFE.set(providers.queries.mir_for_ctfe).unwrap();
            providers.queries.mir_for_ctfe = ctfe;
            ORIGINAL_IDS
                .set(providers.queries.coverage_ids_info)
                .unwrap();
            providers.queries.optimized_mir = instrument;
            providers.queries.coverage_ids_info = ids;
            providers.hooks.is_eligible_for_coverage = eligible;
        });
    }
    fn after_analysis<'tcx>(
        &mut self,
        _: &rustc_interface::interface::Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> Compilation {
        let mut owners = vec![];
        for &id in tcx.mir_keys(()) {
            let kind = tcx.def_kind(id);
            if !eligible(tcx, id) {
                continue;
            }
            let body = tcx.optimized_mir(id);
            let mappings: Vec<_> =
                body.function_coverage_info
                    .as_ref()
                    .map(|info| {
                        info.mappings.iter().map(|m|
                json!({"kind":format!("{:?}",m.kind),"span":span(tcx,m.span,0)})).collect()
                    })
                    .unwrap_or_default();
            let blocks:Vec<_>=body.basic_blocks.iter_enumerated().map(|(bb,data)|json!({
                "id":bb.index(),"cleanup":data.is_cleanup,"terminator":format!("{:?}",data.terminator().kind),
                "successors":data.terminator().successors().map(|b|b.index()).collect::<Vec<_>>(),
                "normal_successors":normal_successors(&data.terminator().kind),
                "terminator_span":span(tcx,data.terminator().source_info.span,0),
                "statements":data.statements.iter().filter(|s|!matches!(s.kind,mir::StatementKind::Coverage(_))).map(|s|json!({"kind":format!("{:?}",s.kind),"span":span(tcx,s.source_info.span,0)})).collect::<Vec<_>>()
            })).collect();
            let dummy = ty::Instance::new_raw(
                id.to_def_id(),
                ty::GenericArgs::for_item(tcx, id.to_def_id(), |p, _| {
                    if let ty::GenericParamDefKind::Lifetime = p.kind {
                        tcx.lifetimes.re_erased.into()
                    } else {
                        tcx.mk_param_from_def(p)
                    }
                }),
            );
            owners.push(json!({"id":owner_id(tcx,id.to_def_id()),"local_id":format!("{:?}",id),
                "name":tcx.def_path_str(id.to_def_id()),"kind":format!("{:?}",kind),"span":span(tcx,tcx.def_span(id),0),
                "mappings":mappings,"blocks":blocks,"dummy_symbol":tcx.symbol_name(dummy).name,
                "explicit_coverage_enabled":tcx.coverage_attr_on(id),
                "mir_sha256":hash(format!("{body:?}").as_bytes())}));
        }
        let mut instances = std::collections::BTreeMap::new();
        for cgu in tcx.collect_and_partition_mono_items(()).codegen_units {
            for item in cgu.items().keys() {
                if let MonoItem::Fn(instance) = item {
                    let body = tcx.instance_mir(instance.def);
                    let symbol = tcx.symbol_name(*instance).name;
                    let record = json!({"symbol":symbol,"owner":owner_id(tcx,instance.def_id()),
                    "kind":format!("{:?}",instance.def),"local":instance.def_id().is_local(),
                    "name":tcx.def_path_str(instance.def_id()),"args":format!("{:?}",instance.args),
                    "coverage":body.function_coverage_info.as_ref().map(|i|json!({"hash":i.function_source_hash,
                        "mappings":i.mappings.iter().map(|m|json!({"kind":format!("{:?}",m.kind),"span":span(tcx,m.span,0)})).collect::<Vec<_>>()
                    }))});
                    if let Some(previous) = instances.insert(symbol, record.clone()) {
                        assert_eq!(previous, record, "ambiguous symbol across codegen units");
                    }
                }
            }
        }
        // Include non-function definitions after expansion and type checking.
        // Constants/statics have compile-time MIR; macro-generated types may
        // have no MIR themselves. Neither is inferred from the source AST.
        let definitions: Vec<_> = tcx.iter_local_def_id().map(|id| {
            let has_mir = tcx.mir_keys(()).contains(&id);
            let runtime = has_mir && eligible(tcx, id);
            let ctfe = (has_mir && !runtime).then(|| format!("{:#?}", tcx.mir_for_ctfe(id)));
            json!({"id":owner_id(tcx,id.to_def_id()),"index":id.local_def_index.as_u32(),
                "name":tcx.def_path_str(id.to_def_id()),"kind":format!("{:?}",tcx.def_kind(id)),
                "span":span(tcx,tcx.def_span(id),0),"role":if runtime {"runtime"} else if has_mir {"compile-time"} else {"declaration"},
                "ctfe_mir":ctfe,"ctfe_sha256":ctfe.as_ref().map(|s|hash(s.as_bytes()))})
        }).collect();
        let sources:Vec<_>=tcx.sess.source_map().files().iter().map(|f|json!({"file":f.name.prefer_local_unconditionally().to_string(),
            "source_id":f.start_pos.0,"compiler_hash":format!("{:?}",f.src_hash),"sha256":f.src.as_ref().map(|s|hash(s.as_bytes())),
            "source":f.src.as_ref().map(|s|s.as_str()),"lines":f.lines().iter().map(|p|p.0).collect::<Vec<_>>()
        })).collect();
        let out = std::env::var("NATIVE_DRIVER_OUTPUT").expect("NATIVE_DRIVER_OUTPUT");
        std::fs::write(
            out,
            serde_json::to_vec_pretty(&json!({"schema":SCHEMA,"rustc_commit":RUSTC_COMMIT,
            "crate_name":tcx.crate_name(rustc_span::def_id::LOCAL_CRATE).as_str(),
            "owners":owners,"definitions":definitions,"instances":instances.values().collect::<Vec<_>>(),"sources":sources}))
            .unwrap(),
        )
        .unwrap();
        Compilation::Continue
    }
}
fn main() -> std::process::ExitCode {
    rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(&std::env::args().collect::<Vec<_>>(), &mut Inventory)
    })
}
