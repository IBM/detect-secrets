import json
import pytest
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.content_checker import ContentChecker
from testing.mocks import mock_file_object

secretExpected = True
noSecretExpected = False
java_source_file_tests = [
		{
			"name":    "Java assignment spanning newline",
			"content": 'String jwtSecret = "dasdasdasdasdasdasdasdasdasddaasdasdasdasdsdhashdsahdhsadhhasdhahdhashdhahdhah";',
			"want":    secretExpected,
		},
		# {
		# 	"name":    "Java string assignment, not a passowrd, but a general statement",
		# 	"content": 'String jwtSecret = "This is a line with more than 2 words.";',
		# 	"want":    noSecretExpected,
		# },
		{
			"name":    "Java assignment",
			"content": 'String password = "xYzzYXxxY123";',
			"want":    secretExpected,
		},
		{
			"name":    "Java constant",
			"content": '  public static final String SSL_PASSWORD = "test1234";',
			"want":    secretExpected,
		},
		{
			"name":    "Read map",
			"content": 'String password = credentials.get("password");',
			"want":    noSecretExpected,
		},
		{
			"name":    "Write map",
			"content": 'credentials.put("password", "xYzzYXxxY123");',
			"want":    secretExpected,
		},
		# {
		# 	"name":    "Write map alternate string",
		# 	"content": 'credentials.put("password", new String("xYzzYXxxY123"));',
		# 	"want":    secretExpected,
		# },
		# {
		# 	"name": "Write to list",
		# 	"content": 'List<String> secrets = ImmutableList.<String>builder().addSecret("ZZZzzzzz").build();',
		# 	"want": secretExpected,
		# },
		# {
		# 	"name": "Set Access Key",
		# 	"content": 'List<String> secrets = ImmutableList.<String>builder().add_access_key("ZZZzzXXXXzzz").build();',
		# 	"want": secretExpected,
		# },
# 		{
# 			"name": "Set App Name",
# 			"content": '''List<String> appProperties = ImmutableList.<String>builder()
# .setAppName("BigSQL-SinkAdapter")
# .build();''',
# 			"want": noSecretExpected,
# 		},
# 		{
# 			"name": "Variable assigment",
# 			"content": '''String secret = mySuperSecret;
#   public static final String SWIFT_AUTH_PROPERTY = Constants.FS_SWIFT2D + AUTH_URL;''',
# 			"want": noSecretExpected,
# 		},
# 		{
# 			"name": "Accessing properties",
# 			"content": '''// various ways of accessing properties
# previousAuthConfig = System.getProperty("java.security.auth.login.config");
# MQEnvironment.password = mqproperties.getProperty("password");''',
# 			"want": noSecretExpected,
# 		},
# 		{
# 			"name": "Secret in comment",
# 			"content": '''/*
# * secret: xYzzYXxxY123
# */''',
# 			"want": secretExpected,
# 		},
# 		{
# 			"name":    "no secret in comments",
# 			"content": '''// Initial author: Randy Weinstein (randy.weinstein@ibm.com)''',
# 			"want":    noSecretExpected,
# 		},
# 		{
# 			"name":    "Secret in url",
# 			"content": '''String url = "https://user"name":MySecretPass0rd!@mycloudant.org";''',
# 			"want":    secretExpected,
# 		},
# 		{
# 			"name":    "Secret in url",
# 			"content": '''String url = System.out.format("https://user"name":MySecretPass0rd!@mycloudant.org:%d", port);''',
# 			"want":    secretExpected,
# 		},
# 		{
# 			"name":    "Secret from variable in url",
# 			"content": 'String url = System.out.format("https://%s:%s@mycloudant.org:%d", user, mySecretPassword, port);',
# 			"want":    noSecretExpected,
# 		},
]



class TestContentChecker:

    @pytest.mark.parametrize(
        'test_case',
        java_source_file_tests,
    )
    def test_java_source_files(self, test_case):
        logic = ContentChecker()
        print("abcse test_cases : ",test_case)
        # for test_case in test_cases:
        print('abcse test_case : ',test_case)
        f = mock_file_object(test_case['content'])
        output = logic.analyze(f, 'mock_filename.java')
        if test_case['want']:
            assert len(output) == 1
        else:
            assert len(output) == 0
        











