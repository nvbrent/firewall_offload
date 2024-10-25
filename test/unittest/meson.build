gtest_dep = dependency('gtest', main : true, required : true) 
gmock_dep = dependency('gmock', main : true, required : true) 
gtest_main_dep = dependency('gtest_main', main : true, required : true) 

test_dependencies = [
    gtest_dep, 
    gmock_dep, 
    gtest_main_dep, 
]

test_nv_opof = executable('test_nv_opof',
    ['test_nv_opof.cpp', 'mocks/rte_flow_mock.cpp'],
    include_directories: ['../../include', 'mocks'],
    dependencies : [app_dependencies, test_dependencies],
    link_with: nv_opof_lib)

test('nv_opof_unittest', test_nv_opof)
