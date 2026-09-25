import importlib


def test_python_v2_function_app_registers_scan_and_remediation() -> None:
    module = importlib.import_module("function_app")
    names = {function.get_function_name() for function in module.app.get_functions()}
    assert names == {"scan", "remediation"}
