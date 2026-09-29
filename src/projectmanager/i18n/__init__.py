from .translator import Translator
from .runtime import tr, set_language, get_language, normalize_language, translate_legacy, translate_presentation, translate_generated, install_tk_hooks, refresh_widget_tree, module_context

__all__=["Translator","tr","set_language","get_language","normalize_language","translate_legacy","translate_presentation","translate_generated","install_tk_hooks","refresh_widget_tree","module_context"]
