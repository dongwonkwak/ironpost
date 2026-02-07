use clap::{Parser, Subcommand};
use std::process::Command;

/// Ironpost 빌드 태스크
#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// eBPF 커널 프로그램 빌드
    BuildEbpf {
        /// 릴리스 모드로 빌드
        #[arg(long)]
        release: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => {
            build_ebpf(release);
        }
    }
}

fn build_ebpf(release: bool) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("crates/ebpf-engine/ebpf");

    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().expect("failed to build eBPF program");
    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    println!("eBPF build succeeded");
}
