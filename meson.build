project('simple_zerohttpd', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

uring_dep = dependency(
  'liburing'
)

ssl_dep = dependency(
  'openssl'
)

add_project_arguments('-g3', language: 'c')

executable('webserver', 'webserver_liburing.c', install : true, dependencies: [uring_dep, ssl_dep])
