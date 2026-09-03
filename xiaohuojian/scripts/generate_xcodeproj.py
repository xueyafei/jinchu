#!/usr/bin/env python3
"""Generate XiaoHuoJian.xcodeproj/project.pbxproj without XcodeGen."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def xid(*parts: str) -> str:
    h = hashlib.md5(("xiaohuojian|" + "|".join(parts)).encode()).hexdigest()[:24].upper()
    return h


def collect(rel: str, suffixes: tuple[str, ...]) -> list[Path]:
    base = ROOT / rel
    out: list[Path] = []
    if not base.exists():
        return out
    for p in sorted(base.rglob("*")):
        if p.is_file() and p.suffix in suffixes:
            if "Preview Content" in p.parts and p.suffix == ".swift":
                continue
            out.append(p)
    return out


def posix(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def main() -> None:
    app_swift = collect("App", (".swift",))
    tun_swift = collect("PacketTunnel", (".swift",))
    shared_swift = collect("Shared", (".swift",))
    plists = [
        ROOT / "App/Info.plist",
        ROOT / "App/XiaoHuoJian.entitlements",
        ROOT / "PacketTunnel/Info.plist",
        ROOT / "PacketTunnel/PacketTunnel.entitlements",
    ]
    assets = ROOT / "App/Assets.xcassets"
    preview = ROOT / "App/Preview Content"

    files: dict[str, dict] = {}

    def add_ref(path: Path, ftype: str, extra: str = "") -> str:
        rel = posix(path)
        i = xid("ref", rel)
        files[rel] = {"id": i, "path": rel, "name": path.name, "ftype": ftype, "extra": extra}
        return i

    for p in app_swift + tun_swift + shared_swift:
        add_ref(p, "sourcecode.swift")
    for p in plists:
        add_ref(p, "text.plist.xml" if p.suffix == ".plist" else "text.plist.entitlements")
    assets_id = add_ref(assets, "folder.assetcatalog")
    preview_id = add_ref(preview, "folder")

    app_product = xid("product", "app")
    tun_product = xid("product", "appex")

    # build files
    def bf(key: str, file_id: str, extra: str = "") -> str:
        return xid("bf", key, file_id)

    app_sources = []  # (bf_id, file_id, name)
    tun_sources = []
    app_resources = []

    for p in app_swift + shared_swift:
        rel = posix(p)
        fid = files[rel]["id"]
        bid = bf("app", fid)
        app_sources.append((bid, fid, p.name))
    for p in tun_swift + shared_swift:
        rel = posix(p)
        fid = files[rel]["id"]
        bid = bf("tun", fid)
        tun_sources.append((bid, fid, p.name))
    app_resources.append((bf("res", assets_id), assets_id, "Assets.xcassets"))
    app_resources.append((bf("res", preview_id), preview_id, "Preview Content"))

    embed_bf = xid("bf", "embed", tun_product)

    # groups
    group_root = xid("group", "root")
    group_app = xid("group", "App")
    group_tun = xid("group", "PacketTunnel")
    group_shared = xid("group", "Shared")
    group_products = xid("group", "Products")
    group_preview = xid("group", "Preview")

    def children_of(prefix: str, file_list: list[Path]) -> list[str]:
        ids = []
        for p in file_list:
            if posix(p).startswith(prefix):
                ids.append(files[posix(p)]["id"])
        return ids

    # nested groups for App/Views etc. — keep it flat-by-folder
    def folder_groups(rel_root: str, swift_files: list[Path], parent_id: str):
        """Return additional group objects keyed by relative folder."""
        folders = {}
        for p in swift_files:
            rel = posix(p)
            parent = str(Path(rel).parent)
            folders.setdefault(parent, []).append(rel)
        # also include non-swift in App
        objs = {}
        for folder, rels in sorted(folders.items()):
            gid = xid("group", folder)
            objs[folder] = {
                "id": gid,
                "name": Path(folder).name,
                "path": Path(folder).name if folder != rel_root else rel_root,
                "full": folder,
                "children": [files[r]["id"] for r in rels],
            }
        return objs

    app_groups = folder_groups("App", app_swift, group_app)
    tun_groups = folder_groups("PacketTunnel", tun_swift, group_tun)
    shared_groups = folder_groups("Shared", shared_swift, group_shared)

    # attach assets/plists into App group
    app_groups["App"]["children"].extend(
        [
            files["App/Info.plist"]["id"],
            files["App/XiaoHuoJian.entitlements"]["id"],
            assets_id,
            group_preview,
        ]
    )
    tun_groups["PacketTunnel"]["children"].extend(
        [
            files["PacketTunnel/Info.plist"]["id"],
            files["PacketTunnel/PacketTunnel.entitlements"]["id"],
        ]
    )

    def attach_subgroups(groups: dict, root_key: str):
        for folder, g in groups.items():
            if folder == root_key:
                continue
            parent = str(Path(folder).parent)
            if parent in groups:
                groups[parent]["children"].append(g["id"])
            elif root_key in groups:
                groups[root_key]["children"].append(g["id"])

    attach_subgroups(app_groups, "App")
    attach_subgroups(tun_groups, "PacketTunnel")
    attach_subgroups(shared_groups, "Shared")

    # phases / configs / targets
    app_src_phase = xid("phase", "app", "src")
    app_fw_phase = xid("phase", "app", "fw")
    app_res_phase = xid("phase", "app", "res")
    app_embed_phase = xid("phase", "app", "embed")
    tun_src_phase = xid("phase", "tun", "src")
    tun_fw_phase = xid("phase", "tun", "fw")
    tun_res_phase = xid("phase", "tun", "res")

    app_target = xid("target", "app")
    tun_target = xid("target", "tun")
    dep_id = xid("dep", "app-tun")
    proxy_id = xid("proxy", "tun")

    proj_cfg_list = xid("cfglist", "project")
    app_cfg_list = xid("cfglist", "app")
    tun_cfg_list = xid("cfglist", "tun")
    proj_debug = xid("cfg", "project", "debug")
    proj_release = xid("cfg", "project", "release")
    app_debug = xid("cfg", "app", "debug")
    app_release = xid("cfg", "app", "release")
    tun_debug = xid("cfg", "tun", "debug")
    tun_release = xid("cfg", "tun", "release")
    project_id = xid("project")

    ne_fw_ref = xid("ref", "fw", "NetworkExtension")
    ne_fw_app = xid("bf", "fw", "app", "NE")
    ne_fw_tun = xid("bf", "fw", "tun", "NE")

    common_proj = """
				ALWAYS_SEARCH_USER_PATHS = NO;
				CLANG_ANALYZER_NONNULL = YES;
				CLANG_ENABLE_MODULES = YES;
				CLANG_ENABLE_OBJC_ARC = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_STRICT_OBJC_MSGSEND = YES;
				GCC_NO_COMMON_BLOCKS = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 16.0;
				SDKROOT = iphoneos;
				SWIFT_VERSION = 5.9;
				TARGETED_DEVICE_FAMILY = 1;
"""

    objects: list[str] = []

    def obj(oid: str, body: str):
        objects.append(f"\t\t{oid} = {{\n{body}\t\t}};")

    # build files
    for bid, fid, name in app_sources + tun_sources + app_resources:
        obj(
            bid,
            f"\t\t\tisa = PBXBuildFile;\n\t\t\tfileRef = {fid};\n",
        )
    obj(
        embed_bf,
        f"\t\t\tisa = PBXBuildFile;\n\t\t\tfileRef = {tun_product};\n\t\t\tsettings = {{ATTRIBUTES = (RemoveHeadersOnCopy, ); }};\n",
    )
    obj(ne_fw_app, f"\t\t\tisa = PBXBuildFile;\n\t\t\tfileRef = {ne_fw_ref};\n")
    obj(ne_fw_tun, f"\t\t\tisa = PBXBuildFile;\n\t\t\tfileRef = {ne_fw_ref};\n")

    # file refs
    for rel, meta in files.items():
        last = Path(rel).name
        extra = ""
        if meta["ftype"] == "folder":
            extra = "\t\t\tsourceTree = \"<group>\";\n"
            obj(
                meta["id"],
                f"\t\t\tisa = PBXFileReference;\n\t\t\tname = \"{last}\";\n\t\t\tpath = \"{rel}\";\n{extra}",
            )
            continue
        obj(
            meta["id"],
            f"\t\t\tisa = PBXFileReference;\n\t\t\tlastKnownFileType = {meta['ftype']};\n\t\t\tpath = \"{last}\";\n\t\t\tsourceTree = \"<group>\";\n",
        )
    obj(
        app_product,
        '\t\t\tisa = PBXFileReference;\n\t\t\texplicitFileType = wrapper.application;\n\t\t\tincludeInIndex = 0;\n\t\t\tpath = XiaoHuoJian.app;\n\t\t\tsourceTree = BUILT_PRODUCTS_DIR;\n',
    )
    obj(
        tun_product,
        '\t\t\tisa = PBXFileReference;\n\t\t\texplicitFileType = "wrapper.app-extension";\n\t\t\tincludeInIndex = 0;\n\t\t\tpath = PacketTunnel.appex;\n\t\t\tsourceTree = BUILT_PRODUCTS_DIR;\n',
    )
    obj(
        ne_fw_ref,
        '\t\t\tisa = PBXFileReference;\n\t\t\tlastKnownFileType = wrapper.framework;\n\t\t\tname = NetworkExtension.framework;\n\t\t\tpath = System/Library/Frameworks/NetworkExtension.framework;\n\t\t\tsourceTree = SDKROOT;\n',
    )

    # groups
    def emit_group(gid: str, name: str, path: str | None, child_ids: list[str]):
        kids = "\n".join(f"\t\t\t\t{c}," for c in child_ids)
        path_line = f'\t\t\tpath = "{path}";\n' if path else ""
        obj(
            gid,
            f'\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n{kids}\n\t\t\t);\n\t\t\tname = "{name}";\n{path_line}\t\t\tsourceTree = "<group>";\n',
        )

    # Fix file refs that live in subgroups: path should be filename only (already).
    # Groups need path = folder name for nested, and App/PacketTunnel/Shared at top with path.

    # Rebuild children: each group's children should be files directly in that folder + subgroup ids
    def rebuild(groups: dict, root_key: str, extra_files: list[str]):
        # reset children to only files in that exact folder
        for folder in groups:
            groups[folder]["children"] = []
        # map files
        # we don't have file list per folder stored except original - reconstruct from swift + extras
        return groups

    # Simpler group model: three top-level groups with ALL files using full relative paths
    # Change file refs to use name + path relative to group.

    # Actually Xcode needs group path + file path. Simplest robust approach:
    # One group per directory with `path` = directory relative to parent.

    emit_group(
        group_preview,
        "Preview Content",
        "Preview Content",
        [preview_id] if False else [],
    )
    # preview folder is a file ref of type folder — put it as child of App

    def all_group_objs(groups: dict, root_key: str):
        # unique children as currently set
        for folder, g in groups.items():
            path = None if False else Path(g["full"]).name
            # For root folders, path is the folder name at repo root
            if folder in ("App", "PacketTunnel", "Shared"):
                path = folder
            emit_group(g["id"], g["name"], path, g["children"])

    all_group_objs(app_groups, "App")
    all_group_objs(tun_groups, "PacketTunnel")
    all_group_objs(shared_groups, "Shared")

    emit_group(group_products, "Products", None, [app_product, tun_product])
    group_fw = xid("group", "Frameworks")
    emit_group(group_fw, "Frameworks", None, [ne_fw_ref])
    emit_group(
        group_root,
        "XiaoHuoJian",
        None,
        [app_groups["App"]["id"], tun_groups["PacketTunnel"]["id"], shared_groups["Shared"]["id"], group_products, group_fw],
    )

    # build phases
    def emit_sources(pid: str, items: list):
        kids = "\n".join(f"\t\t\t\t{bid}," for bid, _, _ in items)
        obj(
            pid,
            f"\t\t\tisa = PBXSourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n{kids}\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n",
        )

    emit_sources(app_src_phase, app_sources)
    emit_sources(tun_src_phase, tun_sources)
    kids = "\n".join(f"\t\t\t\t{bid}," for bid, _, _ in app_resources)
    obj(
        app_res_phase,
        f"\t\t\tisa = PBXResourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n{kids}\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n",
    )
    obj(
        tun_res_phase,
        "\t\t\tisa = PBXResourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n",
    )
    obj(
        app_fw_phase,
        f"\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t\t{ne_fw_app},\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n",
    )
    obj(
        tun_fw_phase,
        f"\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t\t{ne_fw_tun},\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n",
    )
    obj(
        app_embed_phase,
        f"""\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 13;
\t\t\tfiles = (
\t\t\t\t{embed_bf},
\t\t\t);
\t\t\tname = "Embed App Extensions";
\t\t\trunOnlyForDeploymentPostprocessing = 0;
""",
    )

    obj(
        proxy_id,
        f"""\t\t\tisa = PBXContainerItemProxy;
\t\t\tcontainerPortal = {project_id};
\t\t\tproxyType = 1;
\t\t\tremoteGlobalIDString = {tun_target};
\t\t\tremoteInfo = PacketTunnel;
""",
    )
    obj(
        dep_id,
        f"""\t\t\tisa = PBXTargetDependency;
\t\t\ttarget = {tun_target};
\t\t\ttargetProxy = {proxy_id};
""",
    )

    obj(
        app_target,
        f"""\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = {app_cfg_list};
\t\t\tbuildPhases = (
\t\t\t\t{app_src_phase},
\t\t\t\t{app_fw_phase},
\t\t\t\t{app_res_phase},
\t\t\t\t{app_embed_phase},
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t\t{dep_id},
\t\t\t);
\t\t\tname = XiaoHuoJian;
\t\t\tproductName = XiaoHuoJian;
\t\t\tproductReference = {app_product};
\t\t\tproductType = "com.apple.product-type.application";
""",
    )
    obj(
        tun_target,
        f"""\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = {tun_cfg_list};
\t\t\tbuildPhases = (
\t\t\t\t{tun_src_phase},
\t\t\t\t{tun_fw_phase},
\t\t\t\t{tun_res_phase},
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = PacketTunnel;
\t\t\tproductName = PacketTunnel;
\t\t\tproductReference = {tun_product};
\t\t\tproductType = "com.apple.product-type.app-extension";
""",
    )

    obj(
        project_id,
        f"""\t\t\tisa = PBXProject;
\t\t\tattributes = {{
\t\t\t\tBuildIndependentTargetsInParallel = 1;
\t\t\t\tLastSwiftUpdateCheck = 1500;
\t\t\t\tLastUpgradeCheck = 1500;
\t\t\t\tTargetAttributes = {{
\t\t\t\t\t{app_target} = {{
\t\t\t\t\t\tCreatedOnToolsVersion = 15.0;
\t\t\t\t\t}};
\t\t\t\t\t{tun_target} = {{
\t\t\t\t\t\tCreatedOnToolsVersion = 15.0;
\t\t\t\t\t}};
\t\t\t\t}};
\t\t\t}};
\t\t\tbuildConfigurationList = {proj_cfg_list};
\t\t\tcompatibilityVersion = "Xcode 14.0";
\t\t\tdevelopmentRegion = "zh-Hans";
\t\t\thasScannedForEncodings = 0;
\t\t\tknownRegions = (
\t\t\t\ten,
\t\t\t\tBase,
\t\t\t\t"zh-Hans",
\t\t\t);
\t\t\tmainGroup = {group_root};
\t\t\tproductRefGroup = {group_products};
\t\t\tprojectDirPath = "";
\t\t\tprojectRoot = "";
\t\t\ttargets = (
\t\t\t\t{app_target},
\t\t\t\t{tun_target},
\t\t\t);
""",
    )

    def xcconfig(oid: str, name: str, extra: str):
        obj(
            oid,
            f"""\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
{extra}\t\t\t}};
\t\t\tname = {name};
""",
        )

    xcconfig(
        proj_debug,
        "Debug",
        common_proj
        + """
				GCC_DYNAMIC_NO_PIC = NO;
				GCC_OPTIMIZATION_LEVEL = 0;
				MTL_ENABLE_DEBUG_INFO = INCLUDE_SOURCE;
				ONLY_ACTIVE_ARCH = YES;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
""",
    )
    xcconfig(
        proj_release,
        "Release",
        common_proj
        + """
				DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
				MTL_ENABLE_DEBUG_INFO = NO;
				SWIFT_COMPILATION_MODE = wholemodule;
				VALIDATE_PRODUCT = YES;
""",
    )
    app_settings = """
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;
				CODE_SIGN_ENTITLEMENTS = App/XiaoHuoJian.entitlements;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = App/Info.plist;
				INFOPLIST_KEY_CFBundleDisplayName = "小火箭";
				LD_RUNPATH_SEARCH_PATHS = "$(inherited) @executable_path/Frameworks";
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = app.xiaohuojian.vpn;
				PRODUCT_NAME = XiaoHuoJian;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.9;
				TARGETED_DEVICE_FAMILY = 1;
"""
    tun_settings = """
				CODE_SIGN_ENTITLEMENTS = PacketTunnel/PacketTunnel.entitlements;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = PacketTunnel/Info.plist;
				LD_RUNPATH_SEARCH_PATHS = "$(inherited) @executable_path/Frameworks @executable_path/../../Frameworks";
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = app.xiaohuojian.vpn.tunnel;
				PRODUCT_NAME = PacketTunnel;
				SKIP_INSTALL = YES;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.9;
				TARGETED_DEVICE_FAMILY = 1;
"""
    xcconfig(app_debug, "Debug", app_settings)
    xcconfig(app_release, "Release", app_settings)
    xcconfig(tun_debug, "Debug", tun_settings)
    xcconfig(tun_release, "Release", tun_settings)

    def cfglist(oid: str, d: str, r: str):
        obj(
            oid,
            f"""\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t{d},
\t\t\t\t{r},
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
""",
        )

    cfglist(proj_cfg_list, proj_debug, proj_release)
    cfglist(app_cfg_list, app_debug, app_release)
    cfglist(tun_cfg_list, tun_debug, tun_release)

    body = "\n".join(objects)
    pbx = f"""// !$*UTF8*$!
{{
	archiveVersion = 1;
	classes = {{
	}};
	objectVersion = 56;
	objects = {{
{body}
	}};
	rootObject = {project_id};
}}
"""
    out = ROOT / "XiaoHuoJian.xcodeproj" / "project.pbxproj"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(pbx, encoding="utf-8")
    print("wrote", out, "bytes", out.stat().st_size)
    print("app swift", len(app_swift), "tun", len(tun_swift), "shared", len(shared_swift))


if __name__ == "__main__":
    main()
