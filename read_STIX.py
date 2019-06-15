from stix2.workbench import *
from stix2 import FileSystemSource
from stix2validator import validate_file, print_results
from stix2.utils import get_type_from_id
from owlready2 import *
import sys, types


def check_stix_file(path):
    #check the integrity of a stix file
    results = validate_file(path)
    print_results(results)

def get_group_by_alias(src, alias):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('name', '=', alias)
        ])

def get_group_by_name(src, name):
    #get intrusion set and group by name
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('name', '=', name)
        ])

def get_ta_by_name(src, name):
    return src.query([
        Filter('type', '=', 'threat-actor'),
        Filter('name', '=', name)
    ])

def get_ap_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses')

    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])

def get_coa_by_group(src, ap):
    coas = []
    for a in ap:
        mitigations = src.relationships(a.id, 'mitigates', target_only=True)
        coas.append(src.query([
            Filter('type', '=', 'course-of-action'),
            Filter('id', 'in', [c.source_ref for c in mitigations])
        ]))
    return coas
    #TODO other coas


def get_malware_by_group(src, group_stix_id):
    used_objects = [
        r for r in src.relationships(group_stix_id, 'uses')
    ]

    return src.query([
        Filter('type', '=', 'malware'),
        Filter('id', 'in', [r.target_ref for r in used_objects])
    ])

def get_tools_by_group(src, group_stix_id):
    used_objects = [
        r for r in src.relationships(group_stix_id, 'uses')
    ]

    return src.query([
        Filter('type', '=', 'tool'),
        Filter('id', 'in', [r.target_ref for r in used_objects])
    ])

def get_vuln_by_group(src, group_stix_id):
    targeted_objects = [
        r for r in src.relationships(group_stix_id, 'targets')
    ]

    return src.query([
        Filter('type', '=', 'vulnerability'),
        Filter('id', 'in', [r.target_ref for r in targeted_objects])
    ])

def get_identity_by_group(src, malware):
    #TODO FIND ASSOCIATED IDENTITIES
    targeted_objects = [
        r for r in src.relationships(malware, 'created-by')
    ]

    return src.query([
        Filter('type', '=', 'identity'),
        Filter('id', 'in', [r.target_ref for r in targeted_objects])
    ])

def get_identities_by_is(src, group_stix_id):
    used_objects = [
        r for r in src.relationships(group_stix_id, 'attributed-to', target_only=True)
    ]

    return src.query([
        Filter('type', '=', 'identity'),
        Filter('id', 'in', [r.target_ref for r in used_objects])
    ])


def write_file(attack_pattern, malware, tools, course_of_action):
    file = open("stix.txt", "w+")
    #TODO: WRITE TO FILE

    for ap in attack_pattern:
        file.write("------Attack-Pattern-------\n")
        file.write(str(ap))

    for mw in malware:
        file.write("------Malware-------\n")
        file.write(str(mw))

    for tool in tools:
        file.write("------Tool-------\n")
        file.write(str(tool))

    for coa in course_of_action:
        file.write("------Course-of-Action-------\n")
        file.write(str(coa))

    file.close()

def print_all_relationships(src, group, tools, malware, coa):
    relationships_intrusion_set = [
        r for r in src.relationships(group)
    ]

    relationships_tool = [
        r for r in src.relationships(tools)
    ]

    relationships_malware = [
        r for r in src.relationships(malware)
    ]

    relationships_coa = [
        r for r in src.relationships(coa)
    ]


    file = open("rel.txt", "w+")

    for r in relationships_intrusion_set:
        file.write("______Intrusion_Set_Relationship_______\n")
        file.write(str(r))

    for r in relationships_tool:
        file.write("______Tool_Relationship_______\n")
        file.write(str(r))

    for r in relationships_malware:
        file.write("______Malware_Relationship_______\n")
        file.write(str(r))

    for r in relationships_coa:
        file.write("______COA_Relationship_______\n")
        file.write(str(r))

    file.close()
    return

def import_json_to_stix(file):
    with open(file) as json_file:
        obj = parse(json_file, allow_custom=True)
        print(type(obj))

    return obj

def onto_find(json_data):

    onto = get_ontology("file://APTOntology_v1.0.owl").load()

    if json_data.type.lower() == "malware":
        for result in onto.search(subclass_of = onto.Attack):
            try:
                if result.hasMalwareName[0].lower() == json_data.name.lower():
                    print(str(result)[17:])
                    print(result.hasMalwareName[0])
                    print(result.hasMalwareHash)
                    print(result.hasToolName)
                    print(result.hasCoA)
                else:
                    print("False")
            except IndexError:
                continue
            except AttributeError:
                continue



    #print(list(onto.classes()))
    #print(list(onto.object_properties()))
    #print(list(onto.data_properties()))

    #print(onto.search(iri = "*AS*"))

def test(fs):

    group = get_group_by_name(fs, 'APT1')[0]
    print("5%...")
    ap = get_ap_by_group(fs, group)
    print("15%...")
    malware = get_malware_by_group(fs, group)
    print("30%...")
    tools = get_tools_by_group(fs, group)
    print("50%...")
    #print(get_identities_by_is(fs, group))
    #vulnerabilities = get_vuln_by_group(fs, tools[0])
    identities = get_identity_by_group(fs, group)
    #indicators =
    #threat_actor =
    coa = get_coa_by_group(fs, ap)
    print("75%...")
    print(len(coa))
    #print_all_relationships(fs, group, tools, malware, coa[0])
    #observed_data

    write_file(ap, malware, tools, coa)
    print("Finished!")

def import_to_onto(import_json_data):
    onto = get_ontology("file://APTOntology_v1.0.owl").load()
    command = "e"
    if command.lower() == "n":
        class_name = input("Input Class Name:")
        ##TODO Create new Class

    if command.lower() == "e":
        print("Existing Classes:")
        for item in onto.search(subclass_of = onto.Attack):
            print(str(item)[17:])

        class_name = input("Input Class Name:")
        result = onto.search_one(subclass_of = onto.Attack, iri = "*" + class_name + "*")

    if result == None:
        print("Not a valid Classname")
        return

    if import_json_data.type.lower() == "tool":
        print(result.hasToolName)
        result.hasToolName = [import_json_data.name]
        print(result.hasToolName)
    if import_json_data.type.lower() == "malware":
        print(result.hasMalwareName)
        result.hasMalwareName = [import_json_data.name]
        print(result.hasMalwareName)


def main():

    json_file_path = "indicator.txt"
    import_json_file_path = "importindicator.txt"
    json_data = import_json_to_stix(json_file_path)
    import_json_data = import_json_to_stix(import_json_file_path)

    print("Possible Commands: Import, Find, Exit")

    while True:
        command = input("Input Command:")

        if command.lower() == "find":
            #Execute find STIX (=argv[1]) in Ontology
            onto_find(json_data)
        elif command.lower() == "import":
            check_stix_file(import_json_file_path)
            import_to_onto(import_json_data)
                #Execute import of STIX (=argv[1]) in Ontology
        elif command.lower() == "exit":
            command = input("Do you want to save changes made to the Ontology? Y or N")
            if command.lower() == "y":
                onto.save()
            break
        else:
            continue

main()
