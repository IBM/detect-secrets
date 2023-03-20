"""
This plugin runs the CEDP content-checker

Adaptation from : https://github.ibm.com/cognitive-data-platform/cognitive-data-platform/blob/master/tools/cedp_ci/check/passwords.go

Searches for the following named patterns. 
2. SecretFoundInString
3. SetSecret
4. AssignmentSecretFound
5. CommentedSecretFound
6. CommaDelimitedSecret
7. AuthorizationFound
8. BasicAuthorizationFound
9. UrlSecretFound
10. SuspiciousBase64
11. Certificates


Each pattern is defined by a regex and a corresponding match function(matchFcn).

"""



import re
import os
from .base import BasePlugin
from .base import classproperty
from .common.filetype import determine_file_type
from .common.filetype import FileType
from .common.filters import get_aho_corasick_helper
from .common.filters import is_sequential_string
from detect_secrets.core.potential_secret import PotentialSecret


def default_match_fcn(filename,extension,matches):
    return True

class Pattern:

    def __init__(self,name,pattern,match_fcn=None,
        extensions=None,excluded_extensions=[]):
        self.name = name
        self.pattern = pattern
        self.match_fcn = match_fcn
        self.extensions = extensions
        self.excluded_extensions = excluded_extensions
        self.regex = re.compile(self.pattern)


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

# Note: All values here should be lowercase
DENYLIST = [
    Pattern(
        name="SecretFound",
        pattern=secretFoundPattern,
        match_fcn=default_match_fcn,
        excluded_extensions=[".java", ".go", ".py", ".cpp", ".c", ".js", ".scala", ".ts", ".proto", ".yaml", ".yml", ".tpl"]
        ),
    Pattern(
        name="SecretFoundInString",
        pattern=varAndSecretInString,
        match_fcn=default_match_fcn,
        ),
    Pattern(
        name="SetSecret",
        pattern='[\[]*[\'"]*(?i)' + variableRegex + '[\'"]*[\]]*\s*(?:=|=|:|-)\s*[\'"]*\s*[\+,]*\s*' + quotedSecretRegex + '((?:\s*(?:\+*)\s*' + quotedSecretRegex + ')*)',
        match_fcn=default_match_fcn,
        ),
    Pattern(
        name="AssignmentSecretFound",
        pattern='[\[]*[\'"]*(?i)' + variableRegex + '[\'"]*[\]]*\s*(?:=|=|:|-)\s*[\'"]*\s*[\+,]*\s*' + quotedSecretRegex + '((?:\s*(?:\+*)\s*' + quotedSecretRegex + ')*)',
        match_fcn=default_match_fcn,
        ),
    Pattern(
        name="CommentedSecretFound",
        pattern='(?:\*|#|//)(?:\s*\w*)*[\[]*[\'"]*(?i)' + variableRegex + '[\'"]*[\]]*\s*(?:=|=|:)\s*' + secretRegex + '((?:\s*(?:\+*)\s*' + secretRegex + ')*)',
        match_fcn=default_match_fcn,
        ),
    Pattern(
        name="CommaDelimitedSecret",
        pattern='[\'"]?(?i)[\'"]' + variableRegex + '[\'"]\s*[\'"]?\s*[,=:]{1,2}\s*' + quotedSecretRegex,
        match_fcn=default_match_fcn,
        ),
    Pattern(
        name="CommaDelimitedSecret",
        pattern='[\'"]?(?i)[\'"]' + variableRegex + '[\'"]\s*[\'"]?\s*[,=:]{1,2}\s*' + quotedSecretRegex,
        match_fcn=default_match_fcn,
        ),
    
]














class ContentChecker(BasePlugin):
    """
    Scans for secret-sounding variable names.

    This checks if denylisted keywords are present in the analyzed string.
    """
    secret_type = 'Content Checker'

    @classproperty
    def default_options(cls):
        return {}

    @property
    def __dict__(self):
        output = {}
        output.update(super(ContentChecker, self).__dict__)

        return output

    def __init__(self, keyword_exclude=None, exclude_lines_regex=None, automaton=None, **kwargs):
        false_positive_heuristics = []

        super(ContentChecker, self).__init__(
            exclude_lines_regex=exclude_lines_regex,
            false_positive_heuristics=false_positive_heuristics,
            **kwargs
        )

        self.secret_type = 'Content Checker'

        #print('initialization')


    def analyze_string_content(self, string, line_num, filename, output_raw=False):
        print('cc ',filename,':',line_num,',',string)
        output = {}

        for match_string,pattern_name in self.secret_generator(
            string,
            filename=filename,
        ):
            secret = PotentialSecret(
                #pattern_name,
                self.secret_type,
                filename,
                match_string,
                line_num,
                output_raw=output_raw,
            )
            output[secret] = secret
            print('found secret ',pattern_name,' : ','cc ',filename,':',line_num,',',match_string)

        return output

    def secret_generator(self, string, filename):
        _, file_extension = os.path.splitext(filename)
        for pattern in DENYLIST:
            # print('pattern : ',pattern.name)
            # print("pattern : ",pattern.pattern)
            # print('string : ',string.strip())
            if pattern.extensions and (file_extension not in pattern.extensions):
                # print('skipping no in extensions list')
                # print()
                # print()
                continue
            elif file_extension in pattern.excluded_extensions:
                # print('in excluded extensions list')
                # print()
                # print()
                continue

            match = pattern.regex.search(string)
            # print('match : ',match)
            # print()
            # print()
            if match:
                if pattern.match_fcn(filename,file_extension,match):
                    yield match[0],pattern.name


    
























