use clap::{Args, Parser, Subcommand};
use fuzzware::fuzzware_dma_config::FuzzwareDmaConfig;
use hoedur::bintrace::Trace;
use log::{info, warn};
use serde::Serialize;
use std::env;
use std::path::PathBuf;
use std::time::Instant;

pub mod common;
pub mod dma_analysis;
pub mod dma_config;
pub mod dma_snippet;
pub mod fuzzware;
pub mod hoedur;
pub mod mem_map;
pub mod mem_view;
pub mod serialization_helpers;
pub mod summary;

#[derive(Args, Debug)]
pub struct ModelArgs {
    #[arg(long)]
    pub fuzzware_config: PathBuf,
    #[arg(long)]
    pub fuzzware_ram_trace: PathBuf,
    #[arg(long)]
    pub fuzzware_mmio_trace: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Default, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SnippetFormat {
    YAML,
    #[default]
    BIN,
}

#[derive(Args, Debug)]
pub struct SummarizeArgs {
    #[arg(long)]
    pub snipdir: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Model(ModelArgs),
    Summarize(SummarizeArgs),
}

#[derive(Parser, Debug)]
#[command(name = "model-dma")]
#[command(about = "Detect DMA buffers from traces and summarize them into DMA configs", long_about = None)]
struct Cli {
    #[arg(short, long, global = true)]
    pub out_path: Option<PathBuf>,
    #[arg(short, long, global = true, value_enum, default_value_t)]
    pub snip_format: SnippetFormat,

    #[command(subcommand)]
    command: Commands,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn")
    }
    env_logger::init();

    let args = Cli::parse();
    let start = Instant::now();

    match &args.command {
        Commands::Model(ModelArgs {
            fuzzware_config,
            fuzzware_ram_trace,
            fuzzware_mmio_trace,
        }) => {
            let path_ram = fuzzware_ram_trace;
            let path_mmio = fuzzware_mmio_trace;
            let path_config = fuzzware_config;

            let mem_map: mem_map::MemoryMap =
                mem_map::MemoryMap::from_fuzzware_config(&path_config)
                    .expect("Expect to be able to parse fuzzware config");

            let trace: Trace = Trace::from_fuzzware_traces(&path_ram, &path_mmio);
            let duration_trace_parsing = start.elapsed();

            for ev in trace.events.iter().take(5) {
                info!("{:?}", ev);
            }

            let res = dma_analysis::detect_dma(mem_map, trace)?;
            let duration_total = start.elapsed();

            warn!("Overall time taken: {duration_total:?} (parsing: {duration_trace_parsing:?}, detection: {:?}", duration_total-duration_trace_parsing);

            if let Some(out_path) = args.out_path {
                match args.snip_format {
                    SnippetFormat::YAML => serialization_helpers::save_yaml(&res, &out_path)?,
                    SnippetFormat::BIN => serialization_helpers::save_bin(&res, &out_path)?,
                }
            }
        }
        Commands::Summarize(SummarizeArgs { snipdir }) => {
            let snippets: Vec<dma_snippet::DmaAnalysisSnippet> = match args.snip_format {
                SnippetFormat::YAML => dma_snippet::load_snippet_directory(snipdir)?,
                SnippetFormat::BIN => dma_snippet::load_snippet_directory_bin(snipdir)?,
            };

            info!("Loaded {} snippets", snippets.len());
            let duration_snip_parsing = start.elapsed();

            if let Some(res) = summary::summarize_snippets(&snippets) {
                info!("Found a DMA config: {res:#x?}");
                if let Some(out_path) = args.out_path {
                    let fuzzware_compat_res = FuzzwareDmaConfig::from_dma_config(res);
                    serialization_helpers::save_yaml(&fuzzware_compat_res, &out_path)?;
                }
            } else {
                info!("Got no valid DMA config.");
            }

            let duration_total = start.elapsed();
            warn!("Overall time taken: {duration_total:?} (parsing: {duration_snip_parsing:?}, detection: {:?}", duration_total-duration_snip_parsing);
        }
    }

    Ok(())
}
