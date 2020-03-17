#include "pch.h"
#include "CppUnitTest.h"
#include "quicdoq_test\quicdoq_test.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace quicdoqunittest
{
	TEST_CLASS(quicdoqunittest)
	{
	public:
		
		TEST_METHOD(name_parse)
		{
			int ret = name_parse_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(name_format)
		{
			int ret = name_format_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(dns_query_parse)
		{
			int ret = dns_query_parse_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(dns_query_format)
		{
			int ret = dns_query_format_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(rr_name_parse)
		{
			int ret = rr_name_parse_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(basic)
		{
			int ret = quicdoq_basic_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(basic_udp)
		{
			int ret = quicdoq_basic_udp_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(multi_queries)
		{
			int ret = quicdoq_multi_queries_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(multi_udp)
		{
			int ret = quicdoq_multi_udp_test();

			Assert::AreEqual(ret, 0);
		}
	};
}
