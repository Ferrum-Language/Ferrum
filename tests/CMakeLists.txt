add_executable(test_lexer test_lexer.cpp)
target_link_libraries(test_lexer ferrum_core)
add_test(NAME LexerTest COMMAND test_lexer)

add_executable(test_borrow test_borrow.cpp)
target_link_libraries(test_borrow ferrum_core)
add_test(NAME BorrowTest COMMAND test_borrow)
