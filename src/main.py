from icon import images
from utils import *
import zstandard as zs
import os
import sys
import argparse
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import tkinter.messagebox as messagebox
from tkinter import PhotoImage
from restbl import (
    Restbl, MergeMods, GenerateRestblFromSingleMod,
    MergeChangelogs, apply_patches, gen_changelog, get_correct_path
)

IS_SWITCH_BUILD = False
try:
    with open(get_correct_path('build_flags/switch_build.flag'), 'r') as f:
        IS_SWITCH_BUILD = True
except:
    pass

def welcome():
    return """
              / \\\\
             /   \\\\
            /_____\\\\
           /\\\\    /\\\\
          /  \\\\  /  \\\\
         /____\\\\/____\\\\
   __________________________

   - TotK RESTBL Calculator -
   __________________________
"""
# For pyinstaller relative paths
def get_correct_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

ctk.set_appearance_mode("dark")

if IS_SWITCH_BUILD:
    ctk.set_widget_scaling(1.5)

def open_tool():
    app = ctk.CTk()
    app.title('RESTBL Calculator 2.0.0')
    if os.name == 'nt':
        app.iconbitmap(images)
    else:
        icon = PhotoImage(file=images)
        app.iconphoto(True, icon)
    print(welcome())
    restbl_to_patch = ''

    def on_completion():
        messagebox.showinfo("Success", "The resource table file was successfully generated")

    def calculate_single_mod():
        mod_path = single_mod_path_entry.get()
        if not os.path.isdir(mod_path):
            messagebox.showerror("Error", "Please enter a correct mod folder path.")
            return
        version = version_map[version_combobox.get()]
        calculate_single_mod_button.configure(text="Please wait...", fg_color="#26ac15", text_color="#4f4f4f", state="disabled"), app.update()
        GenerateRestblFromSingleMod(mod_path, restbl_to_patch, version, compress_var.get(), use_checksums_var.get(), verbose_var.get(), dev_mode_var.get())
        calculate_single_mod_button.configure(text="Calculate (single mod)", fg_color="#1f6aa5", text_color="white", state="normal"), app.update(), on_completion()

    def calculate_restbl():
        mod_path = mod_path_entry.get()
        if not os.path.isdir(mod_path):
            messagebox.showerror("Error", "Please enter a correct mod folder path.")
            return
        version = version_map[version_combobox.get()]
        calculate_restbl_button.configure(text="Please wait...", fg_color="#26ac15", text_color="#4f4f4f", state="disabled"), app.update()
        MergeMods(mod_path, restbl_to_patch, version, compress_var.get(), delete_var.get(), smart_analyze_var.get(), use_checksums_var.get(), verbose_var.get(), dev_mode_var.get())
        calculate_restbl_button.configure(text="Calculate RESTBL", fg_color="#1f6aa5", text_color="white", state="normal"), app.update(), on_completion()

    version_map = {
        '1.0.0': 100,
        '1.1.0': 110,
        '1.1.1': 111,
        '1.1.2': 112,
        '1.2.0': 120,
        '1.2.1': 121,
        '1.4.0': 140,
        '1.4.1': 141,
    }

    # Options Frame
    options_frame = ctk.CTkFrame(master=app)
    options_frame.pack(pady=5, padx=20, fill='both', expand=True)

    # Checkboxes
    compress_var = ctk.CTkCheckBox(master=options_frame, text="Compress")
    compress_var.grid(row=0, column=0, padx=10, pady=5, sticky='nsew')
    compress_var.select()
    smart_analyze_var = ctk.CTkCheckBox(master=options_frame, text="Use Existing RESTBL")
    smart_analyze_var.grid(row=0, column=1, padx=10, pady=5, sticky='nsew')
    delete_var = ctk.CTkCheckBox(master=options_frame, text="Delete Existing RESTBL")
    delete_var.grid(row=0, column=2, padx=10, pady=5, sticky='nsew')
    use_checksums_var = ctk.CTkCheckBox(master=options_frame, text="Use Checksums")
    use_checksums_var.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
    use_checksums_var.select()
    verbose_var = ctk.CTkCheckBox(master=options_frame, text="Verbose")
    verbose_var.grid(row=1, column=1, padx=10, pady=5, sticky='nsew')
    dev_mode_var = ctk.CTkCheckBox(master=options_frame, text="Dev Mode")
    dev_mode_var.grid(row=1, column=2, padx=10, pady=5, sticky='nsew')

    # Version selection
    version_container = ctk.CTkFrame(master=options_frame)
    version_container.grid(row=2, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
    version_center_container = ctk.CTkFrame(master=version_container)
    version_center_container.pack(fill='x', expand=True)
    version_elements = ctk.CTkFrame(master=version_center_container)
    version_elements.pack(expand=True)
    version_label = ctk.CTkLabel(master=version_elements, text="TotK Version:")
    version_label.pack(side='left', padx=(0, 5))
    version_combobox = ctk.CTkComboBox(master=version_elements, values=list(version_map.keys()), width=100, state="readonly")
    version_combobox.pack(side='left')
    version_combobox.set("1.4.1")

    # Set column configurations to distribute space evenly
    options_frame.grid_columnconfigure(0, weight=1)
    options_frame.grid_columnconfigure(1, weight=1)
    options_frame.grid_columnconfigure(2, weight=1)

    # Event handling for actions
    def handle_actions():
        global version
        version = version_map[version_combobox.get()]

    # Single Mod Path Frame
    single_mod_path_frame = ctk.CTkFrame(master=app)
    single_mod_path_frame.pack(pady=5, padx=20, fill='both', expand=True)

    single_mod_path_label = ctk.CTkLabel(master=single_mod_path_frame, text="Single Mod / Switch(Atmosphere):")
    single_mod_path_label.pack()
    single_mod_path_container = ctk.CTkFrame(master=single_mod_path_frame)
    single_mod_path_container.pack(fill='x', padx=10)
    single_mod_path_entry = ctk.CTkEntry(master=single_mod_path_container, width=380)
    single_mod_path_entry.pack(side='left', fill='x', expand=True)
    single_mod_path_browse = ctk.CTkButton(master=single_mod_path_container, text="Browse", command=lambda: update_entry(single_mod_path_entry))
    single_mod_path_browse.pack(side='right', padx=5)
    
    if IS_SWITCH_BUILD:
        single_mod_path_entry.insert(0, "/flash/atmosphere/contents/0100F2C0115B6000")
        calculate_single_mod_button = ctk.CTkButton(master=app, text="Calculate RESTBL", command=lambda: [handle_actions(), calculate_single_mod()])
        calculate_single_mod_button.pack(pady=10)
    else:
        calculate_single_mod_button = ctk.CTkButton(master=app, text="Calculate RESTBL", command=lambda: [handle_actions(), calculate_single_mod()])
        calculate_single_mod_button.pack(pady=10)

        # Mod Path Frame
        mod_path_frame = ctk.CTkFrame(master=app)
        mod_path_frame.pack(pady=5, padx=20, fill='both', expand=True)

        mod_path_label = ctk.CTkLabel(master=mod_path_frame, text="Calculate RESTBL for Multiple Mods:")
        mod_path_label.pack()
        mod_path_container = ctk.CTkFrame(master=mod_path_frame)
        mod_path_container.pack(fill='x', padx=5)
        mod_path_entry = ctk.CTkEntry(master=mod_path_container, width=380)
        mod_path_entry.pack(side='left', fill='x', expand=True)
        mod_path_browse = ctk.CTkButton(master=mod_path_container, text="Browse", command=lambda: update_entry(mod_path_entry))
        mod_path_browse.pack(side='right', padx=5)

        calculate_restbl_button = ctk.CTkButton(master=app, text="Calculate RESTBL", command=lambda: [handle_actions(), calculate_restbl()])
        calculate_restbl_button.pack(pady=10)

        # Advanced Options Frame
        advanced_frame = ctk.CTkFrame(master=app)
        advanced_frame.pack(pady=5, padx=20, fill='both', expand=True)

        # Advanced Options Header
        advanced_header = ctk.CTkFrame(master=advanced_frame)
        advanced_header.pack(fill='x', padx=5, pady=5)
        
        advanced_label = ctk.CTkLabel(master=advanced_header, text="Advanced Options", font=("Arial", 14, "bold"))
        advanced_label.pack(side='left', padx=5)
        
        advanced_toggle = ctk.CTkButton(master=advanced_header, text="▼", width=30, command=lambda: toggle_advanced())
        advanced_toggle.pack(side='right', padx=5)

        # Container for advanced options
        advanced_content = ctk.CTkFrame(master=advanced_frame)
        advanced_content.pack(fill='both', expand=True, padx=5, pady=5)

        # Merge RESTBLs Frame
        merge_restbl_frame = ctk.CTkFrame(master=advanced_content)
        merge_restbl_frame.pack(pady=5, padx=5, fill='both', expand=True)

        merge_restbl_label = ctk.CTkLabel(master=merge_restbl_frame, text="Merge Two RESTBL Files:")
        merge_restbl_label.pack()
        
        restbl_path0_container = ctk.CTkFrame(master=merge_restbl_frame)
        restbl_path0_container.pack(fill='x', padx=5)
        restbl_path0_label = ctk.CTkLabel(master=restbl_path0_container, text="RESTBL Path 1:", width=120)
        restbl_path0_label.pack(side='left', padx=5)
        restbl_path0_entry = ctk.CTkEntry(master=restbl_path0_container, width=380)
        restbl_path0_entry.pack(side='left', fill='x', expand=True)
        restbl_path0_browse = ctk.CTkButton(master=restbl_path0_container, text="Browse", width=80, command=lambda: update_entry(restbl_path0_entry))
        restbl_path0_browse.pack(side='right', padx=5)

        restbl_path1_container = ctk.CTkFrame(master=merge_restbl_frame)
        restbl_path1_container.pack(fill='x', padx=5)
        restbl_path1_label = ctk.CTkLabel(master=restbl_path1_container, text="RESTBL Path 2:", width=120)
        restbl_path1_label.pack(side='left', padx=5)
        restbl_path1_entry = ctk.CTkEntry(master=restbl_path1_container, width=380)
        restbl_path1_entry.pack(side='left', fill='x', expand=True)
        restbl_path1_browse = ctk.CTkButton(master=restbl_path1_container, text="Browse", width=80, command=lambda: update_entry(restbl_path1_entry))
        restbl_path1_browse.pack(side='right', padx=5)

        merge_restbl_button = ctk.CTkButton(master=advanced_content, text="Merge RESTBLs", command=lambda: [handle_actions(), merge_restbls()])
        merge_restbl_button.pack(pady=10)

        # Generate Changelog Frame
        changelog_frame = ctk.CTkFrame(master=advanced_content)
        changelog_frame.pack(pady=5, padx=5, fill='both', expand=True)

        changelog_label = ctk.CTkLabel(master=changelog_frame, text="Generate Changelog:")
        changelog_label.pack()
        
        log_restbl_container = ctk.CTkFrame(master=changelog_frame)
        log_restbl_container.pack(fill='x', padx=5)
        log_restbl_label = ctk.CTkLabel(master=log_restbl_container, text="RESTBL Path:", width=120)
        log_restbl_label.pack(side='left', padx=5)
        log_restbl_entry = ctk.CTkEntry(master=log_restbl_container, width=380)
        log_restbl_entry.pack(side='left', fill='x', expand=True)
        log_restbl_browse = ctk.CTkButton(master=log_restbl_container, text="Browse", width=80, command=lambda: update_entry(log_restbl_entry))
        log_restbl_browse.pack(side='right', padx=5)
        format_container = ctk.CTkFrame(master=changelog_frame)
        format_container.pack(fill='x', padx=5, pady=(10, 0))
        format_center_container = ctk.CTkFrame(master=format_container)
        format_center_container.pack(fill='x', expand=True)
        format_elements = ctk.CTkFrame(master=format_center_container)
        format_elements.pack(expand=True)
        format_label = ctk.CTkLabel(master=format_elements, text="Format:")
        format_label.pack(side='left', padx=(0, 5))
        format_combobox = ctk.CTkComboBox(master=format_elements, values=['json', 'rcl', 'yaml'], width=100, state="readonly")
        format_combobox.pack(side='left')
        format_combobox.set("json")

        generate_changelog_button = ctk.CTkButton(master=advanced_content, text="Generate Changelog", command=lambda: [handle_actions(), generate_changelog()])
        generate_changelog_button.pack(pady=10)

        # Apply Patches Frame
        patches_frame = ctk.CTkFrame(master=advanced_content)
        patches_frame.pack(pady=5, padx=5, fill='both', expand=True)

        patches_label = ctk.CTkLabel(master=patches_frame, text="Apply Patches:")
        patches_label.pack()
        
        patch_restbl_container = ctk.CTkFrame(master=patches_frame)
        patch_restbl_container.pack(fill='x', padx=5)
        patch_restbl_label = ctk.CTkLabel(master=patch_restbl_container, text="RESTBL to patch:", width=120)
        patch_restbl_label.pack(side='left', padx=5)
        patch_restbl_entry = ctk.CTkEntry(master=patch_restbl_container, width=380)
        patch_restbl_entry.pack(side='left', fill='x', expand=True)
        patch_restbl_browse = ctk.CTkButton(master=patch_restbl_container, text="Browse", width=80, command=lambda: update_entry(patch_restbl_entry))
        patch_restbl_browse.pack(side='right', padx=5)

        patches_path_container = ctk.CTkFrame(master=patches_frame)
        patches_path_container.pack(fill='x', padx=5)
        patches_path_label = ctk.CTkLabel(master=patches_path_container, text="Folder with patches:", width=120)
        patches_path_label.pack(side='left', padx=5)
        patches_path_entry = ctk.CTkEntry(master=patches_path_container, width=380)
        patches_path_entry.pack(side='left', fill='x', expand=True)
        patches_path_browse = ctk.CTkButton(master=patches_path_container, text="Browse", width=80, command=lambda: update_entry(patches_path_entry))
        patches_path_browse.pack(side='right', padx=5)

        apply_patches_button = ctk.CTkButton(master=advanced_content, text="Apply Patches", command=lambda: [handle_actions(), apply_patches_ui()])
        apply_patches_button.pack(pady=10)

        advanced_content.pack_forget()

        def toggle_advanced():
            if advanced_content.winfo_ismapped():
                advanced_content.pack_forget()
                advanced_toggle.configure(text="▼")
            else:
                advanced_content.pack(fill='both', expand=True, padx=5, pady=5)
                advanced_toggle.configure(text="▲")

    exit_button = ctk.CTkButton(master=app, text="Exit", command=app.destroy, width=135, height=40, fg_color='#C70039', hover_color='#E57373')
    exit_button.pack(pady=10, padx=20, side='right')

    def merge_restbls():
        restbl_path0 = restbl_path0_entry.get()
        restbl_path1 = restbl_path1_entry.get()
        if not (os.path.isfile(restbl_path0) and os.path.isfile(restbl_path1) and 
                (restbl_path0.endswith(('.rsizetable', '.rsizetable.zs')) and 
                restbl_path1.endswith(('.rsizetable', '.rsizetable.zs')))):
            messagebox.showerror("Error", "Please select two valid RESTBL files")
            return
        merge_restbl_button.configure(text="Please wait...", fg_color="#26ac15", text_color="#4f4f4f", state="disabled"), app.update()
        restbl0 = Restbl(restbl_path0)
        restbl1 = Restbl(restbl_path1)
        changelog0, changelog1, restbl = restbl0.GenerateChangelog(), restbl1.GenerateChangelog(), restbl0
        print("Calculating merged changelog...")
        changelog = MergeChangelogs([changelog0, changelog1])
        print("Applying changes...")
        restbl.ApplyChangelog(changelog)
        restbl.Reserialize()
        if compress_var.get():
            with open(restbl.filename, 'rb') as file:
                data = file.read()
            if os.path.exists(restbl.filename + '.zs'):
                os.remove(restbl.filename + '.zs')
            os.rename(restbl.filename, restbl.filename + '.zs')
            with open(restbl.filename + '.zs', 'wb') as file:
                compressor = zs.ZstdCompressor()
                file.write(compressor.compress(data))
        print("Finished")
        merge_restbl_button.configure(text="Merge RESTBLs", fg_color="#1f6aa5", text_color="white", state="normal"), app.update()
        on_completion()

    def generate_changelog():
        log_restbl_path = log_restbl_entry.get()
        if not (os.path.isfile(log_restbl_path) and 
                (log_restbl_path.endswith(('.rsizetable', '.rsizetable.zs')))):
            messagebox.showerror("Error", "Please select a valid RESTBL file")
            return
        generate_changelog_button.configure(text="Please wait...", fg_color="#26ac15", text_color="#4f4f4f", state="disabled"), app.update()
        gen_changelog(log_restbl_path, format_combobox.get())
        generate_changelog_button.configure(text="Generate Changelog", fg_color="#1f6aa5", text_color="white", state="normal"), app.update()
        on_completion()

    def apply_patches_ui():
        patch_restbl = patch_restbl_entry.get()
        patches_path = patches_path_entry.get()
        if not (os.path.isfile(patch_restbl) and os.path.isdir(patches_path) and 
                (patch_restbl.endswith(('.rsizetable', '.rsizetable.zs')))):
            messagebox.showerror("Error", "Please select a valid RESTBL file and patches folder")
            return
        apply_patches_button.configure(text="Please wait...", fg_color="#26ac15", text_color="#4f4f4f", state="disabled"), app.update()
        apply_patches(patch_restbl, patches_path, compressed=compress_var.get())
        apply_patches_button.configure(text="Apply Patches", fg_color="#1f6aa5", text_color="white", state="normal"), app.update()
        on_completion()

    app.mainloop()

def update_entry(entry_widget):
    directory = filedialog.askdirectory()
    if directory:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, directory)

if __name__ == "__main__":
    # Check if any command-line arguments were passed
    if len(sys.argv) > 1:
        print(welcome())
        parser = argparse.ArgumentParser(description='RESTBL Tool', formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-a', '--action', choices=['merge-mods', 'merge-restbl', 'generate-changelog', 'apply-patches', 'single-mod'], required=True, help='Action to perform')
        parser.add_argument('-c', '--compress', action='store_true', help='Compress the output')
        parser.add_argument('-v', '--verbose', action='store_true', help='Print the list of edited files from mods')
        parser.add_argument('-dev', '--dev-mode', action='store_true', help='Multiply the calculated sizes by a factor of 1.3 for testing')
        parser.add_argument('-cs', '--use-checksums', action='store_true', help='[Recommended] Use checksums')
        parser.add_argument('-m', '--mod-path', type=str, help='Mandatory for actions "merge-mods" and "single-mod"')
        parser.add_argument('-r', '--restbl-path', type=str, help='(Optional) Path to a RESTBL file to patch when calculating entries for mods')
        parser.add_argument('-ver', '--version', type=int, default=141, help='(Optional) TotK version - default: 141')

        # Arguments for 'merge-mods' action
        merge_mods_group = parser.add_argument_group('merge-mods')
        merge_mods_group.add_argument('-u', '--use-existing-restbl', action='store_true', help='(Optional) Use existing RESTBL')
        merge_mods_group.add_argument('-d', '--delete-existing-restbl', action='store_true', help='(Optional) Delete existing RESTBL')

        # Arguments for 'merge-restbl' action
        merge_restbl_group = parser.add_argument_group('merge-restbl')
        merge_restbl_group.add_argument('-r0', '--restbl-path0', type=str, help='(Mandatory) Path to the first RESTBL file to merge')
        merge_restbl_group.add_argument('-r1', '--restbl-path1', type=str, help='(Mandatory) Path to the second RESTBL file to merge')

        # Arguments for 'generate-changelog' action
        gen_changelog_group = parser.add_argument_group('generate-changelog')
        gen_changelog_group.add_argument('-l', '--log-restbl-path', type=str, help='(Mandatory) Path to the RESTBL file for generating changelog')
        gen_changelog_group.add_argument('-f', '--format', choices=['json', 'rcl', 'yaml'], help='(Mandatory) Format of the changelog')

        # Arguments for 'apply-patches' action
        apply_patches_group = parser.add_argument_group('apply-patches')
        apply_patches_group.add_argument('-p', '--patch-restbl', type=str, help='(Mandatory) Path to the RESTBL file to patch')
        apply_patches_group.add_argument('-pp', '--patches-path', type=str, help='(Mandatory) Path to the folder containing patches (rcl, yaml, json)')

        args = parser.parse_args()
        version = args.version

        if args.action == 'merge-mods':
            if args.restbl_path is None:
                restbl_path = ''
            else:
                restbl_path = args.restbl_path
            MergeMods(args.mod_path, restbl_path, version, args.compress, args.delete_existing_restbl, args.use_existing_restbl, args.use_checksums, args.verbose, args.dev_mode)
        elif args.action == 'merge-restbl':
            restbl_path0 = args.restbl_path0
            restbl_path1 = args.restbl_path1
            restbl0 = Restbl(restbl_path0)
            restbl1 = Restbl(restbl_path1)
            changelog0, changelog1, restbl = restbl0.GenerateChangelog(), restbl1.GenerateChangelog(), restbl0
            print("Calculating merged changelog...")
            changelog = MergeChangelogs([changelog0, changelog1])
            print("Applying changes...")
            restbl.ApplyChangelog(changelog)
            restbl.Reserialize()
            if args.compress:
                with open(restbl.filename, 'rb') as file:
                    data = file.read()
                if os.path.exists(restbl.filename + '.zs'):
                    os.remove(restbl.filename + '.zs')
                os.rename(restbl.filename, restbl.filename + '.zs')
                with open(restbl.filename + '.zs', 'wb') as file:
                    compressor = zs.ZstdCompressor()
                    file.write(compressor.compress(data))
            print("Finished")
        elif args.action == 'generate-changelog':
            gen_changelog(args.log_restbl_path, args.format)
        elif args.action == 'apply-patches':
            apply_patches(args.patch_restbl, args.patches_path, compressed=args.compress)
        elif args.action == 'single-mod':
            if args.restbl_path is None:
                restbl_path = ''
            else:
                restbl_path = args.restbl_path
            GenerateRestblFromSingleMod(args.mod_path, restbl_path, version, args.compress, args.use_checksums, args.verbose, args.dev_mode)
    else:
        open_tool()
