def convert_external_variables(ext_var_dict):
    output = []
    for ext_var in ext_var_dict:
        output.append('-d {}={}'.format(ext_var, ext_var_dict[ext_var]))
    return " ".join(sorted(output))
