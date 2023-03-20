import re

assignmentPattern = '(\S+)\s*(?:=|:=|:|<-)\s*(.+)'
quotedStringPattern = '^(?:"([^"]+)"|\'([^\']+)\'|\'\'\'([^\']+)\'\'\'|"""([^"]+)"""|([^\'"\s]+))$'

#restrictedPatterns is an enumeration of each pattern that we are searching for
#in the code base.  The matching of any one of these will cause a CEDP CI failure
#across all readiness levels.

variableRegex = '[\'"(]*([\w\.]*(?:password|dburl|token|passwd|key|access[_-]?key[_-]?id|access[_-]?key|secret[_-]?key|secret|auth[a-zA-Z_]*|cred|pwd|xclientid))[\'")]*'

#secretRegex should ideally span secrets which may or may not be embedded in quotes, hence they shouldn't contain space.
secretRegex = '[\\\(\'"]*(?:(?:basic|token)\s+)?([^\'";\(\),\s$]+)(?:())?[\'"\)\\;]?'

#quotedSecretRegex spans secrets embedded in quotes, so they can contain space.
quotedSecretRegex = '[\\\(]*[\'"]+' + '[\\\(\'"]*(?:(?:basic|token)\s+)?([^\'";\(\),$]+)(?:())?[\'"\)\\;]?' + '[\'"\)\\;]*'

secretFoundPattern = '(?i)' + variableRegex + '\s*[=:]{1,2}\s*' + secretRegex

#varAndSecretInString spans strings like "otherProps=whatever;PWD=debTFvgjm579&*%gjvH;PORT=8080;"
varAndSecretInString = '(?:' + '"(?:[^"]*?)' + secretFoundPattern + '(?:[^"]*)"' + '|' +\
    '\'(?:[^\']*?)' + secretFoundPattern + '(?:[^\']*)\'' + '|' + \
    '\'\'\'(?:[^\']*?)' + secretFoundPattern + '(?:[^\']*)\'\'\'' + '|' + \
    '"""(?:[^"]*?)' + secretFoundPattern + '(?:[^"]*)"""' + ')'

assignment_secret_found = '[\[]*[\'"]*(?i)' + variableRegex+ '[\'"]*[\]]*\s*(?:=|=|:|-)\s*[\'"]*\s*[\+,]*\s*' + quotedSecretRegex + '((?:\s*(?:\+*)\s*' + quotedSecretRegex + ')*)'


# variableRegex = '[\'"(]*([\w\.]*(?:password|dburl|token|passwd|key|access[_-]?key[_-]?id|access[_-]?key|secret[_-]?key|secret|auth[a-zA-Z_]*|cred|pwd|xclientid))[\'")]*'
regex_string = quotedSecretRegex
regex_val = re.compile(regex_string)
print('regex : ',regex_val)
search_string = 'String jwtSecret = "dasdasdasdasdasdasdasdasdasddaasdasdasdasdsdhashdsahdhsadhhasdhahdhashdhahdhah";'
print("search_string : ",search_string)
match_obj = regex_val.findall(search_string)
index = 0
for matchval in match_obj:
    print('match '+str(index)+' : ',matchval)
    index +=1


