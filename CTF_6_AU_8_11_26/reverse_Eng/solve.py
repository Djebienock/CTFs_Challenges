import angr
import claripy

project = angr.Project('./fcunlock', auto_load_libs=False)

# Créer 24 variables symboliques pour le code de service
flag_chars = [claripy.BVS(f'c_{i}', 8) for i in range(24)]

# On garde argv[0] comme une chaîne classique (autorisée par angr)
# et argv[1] contient nos 24 octets symboliques
flag_expr = claripy.Concat(*(flag_chars + [claripy.BVV(0, 8)]))

state = project.factory.entry_state(args=['./fcunlock', flag_expr])

# Contraintes pour forcer des caractères imprimables
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

simgr = project.factory.simulation_manager(state)

print("Recherche du chemin de succès...")

simgr.explore(
    find=lambda s: b"ACCESS DENIED" not in s.posix.dumps(1),
    avoid=lambda s: b"ACCESS DENIED" in s.posix.dumps(1)
)

if simgr.found:
    solution_state = simgr.found[0]
    solution = solution_state.solver.eval(flag_expr, cast_to=bytes)
    print("\n[+] FLAG TROUVÉ !")
    print("Code de service :", solution.decode('utf-8', errors='ignore'))
else:
    print("[-] Aucune solution trouvée.")
