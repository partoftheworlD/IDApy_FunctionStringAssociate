import idc
import idautils
import idaapi
import ida_bytes

class StringException(Exception):
    pass

def get_string_at(addr):
    try:
        s_type = idc.get_str_type(addr)
        if s_type == -1 or s_type is None:
            return None

        s_bytes = ida_bytes.get_strlit_contents(addr, -1, s_type)
        if s_bytes:
            try:
                return s_bytes.decode("utf-8", errors="ignore").strip()
            except:
                return None
    except TypeError:
        raise StringException()

def save_existing_comments(func_ea):
    bc = []
    for cmt_type in [0, 1]:
        comment = idc.get_func_cmt(func_ea, cmt_type)
        if comment:
            if not comment.startswith("STR"):
                bc.append(comment)
    return bc if bc else None

def clear_comments(func_ea):
    idc.set_func_cmt(func_ea, "", 0)
    idc.set_func_cmt(func_ea, "", 1)

def run():
    print(
        "\nStringsFunctionAssociate v0.12 by partoftheworlD! Last Changes <2026-01-13 20:51:12.814613>\n[+]Launching...\n"
    )
    count = 0
    total = idaapi.get_func_qty()

    for func_ea in idautils.Functions():
        strings_in_func = []

        coms = save_existing_comments(func_ea)
        if coms:
            strings_in_func.extend(coms)

        clear_comments(func_ea)

        f_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        for head in idautils.Heads(func_ea, f_end):
            for xref in idautils.DataRefsFrom(head):
                s = get_string_at(xref)
                if s and len(s) > 2:
                    cs = s.translate(str.maketrans({"\n": " ", "\r": " "}))
                    if cs not in strings_in_func:
                        strings_in_func.append(cs)

        if strings_in_func:
            comments = " ".join([f'"{x}"' if " " in x else x for x in strings_in_func])
            idc.set_func_cmt(func_ea, f"STR {len(strings_in_func)}# {comments}", 1)
            count += len(strings_in_func)

    print(f"[+]Well done! Added {count} strings in {total} functions")

class Handler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        run()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PluginButton(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Associate functions"
    help = "https://github.com/partoftheworlD/IDApy_FunctionStringAssociate/"
    wanted_name = "Strings Function Associate"
    wanted_hotkey = ""

    def init(self):
        try:
            self._install_plugin()
        except Exception:
            form = idaapi.get_current_widget()
        return idaapi.PLUGIN_KEEP

    def _install_plugin(self):
        self.init()

    def term(self):
        pass

    def run(self, arg=0):
        h = Handler()
        h.activate(self)

def PLUGIN_ENTRY():
    return PluginButton()
