from xml.etree import ElementTree, ElementInclude
import json
from collections import OrderedDict


class create_json:

    file_path = "include_living_of_the_land.xml"

    def pars_xml(self, file_path):
        tree = ElementTree.parse(file_path)
        root = tree.getroot()
        return root

    def get_xml(self):
        root = self.pars_xml(self.file_path)
        xml_path = ['.//OriginalFileName', './/Image']
        xml_lines = []
        for path in xml_path:
            for i in root.findall(path):
                json_format = {'RuleName': '', 'Weigth': '', 'Rule': {'EventID': '', 'EventDataName': '', 'Expr': '', 'Type': ''}, 'Comment': ''}
                for j in json_format:
                    if j == 'Rule':
                        for rule in json_format[j]:
                            if rule == 'EventID':
                                json_format[j][rule] = "EventIdOneFive"
                            elif rule == 'EventDataName':
                                json_format[j][rule] = i.tag
                            elif rule == 'Expr':
                                json_format[j][rule] = i.text
                            elif rule == 'Type':
                                json_format[j][rule] = "String"
                    else:
                        json_format[j] = ""
                xml_lines.append(json_format)
        print(xml_lines)
        return xml_lines


    def xml_to_json(self):
        json_list = self.get_xml()
        with open('First_filtering.json', 'w', encoding='utf-8') as json_file:
            json.dump(json_list, json_file, ensure_ascii=False, indent='\t')


if __name__ == '__main__':
    test = create_json()
    test.xml_to_json()