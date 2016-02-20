//
// Assume that grunt-cli has been installed at the npm -g level, so can run grunt
//

module.exports = function (grunt) {
  'use strict';

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    buddyjs: {
      src: ['lib/*.js', 'test/*.js'],
      options: {
        ignore: [0, 1, 2, 3, 4, 16, 32]
      }
    },

    jshint: {
      all: ['Gruntfile.js',
        'lib/*.js',
        'test/*.js'],
      options: {
        predef: ['describe', 'it', 'before', 'after'],
        exported: ['should'],
        curly: true,
        indent: 2,
        node: true,
        undef: true,
        unused: true,
        eqeqeq: true,
        strict: true
      }
    },

    shell: {
      npmupdate: {
        command: ['echo running npm update', 'npm update'].join('&&')
      }
    },

    mochaTest: {
      unitTest: {
        options: {
          reporter: 'spec'
        },
        src: ['test/*.js']
      },

      // limit tests as not AWS credentials in codeship
      codeshipTest: {
        options: {
          reporter: 'spec'
        },
        src: ['test/testFormatUtils.js', 'test/testNodeCryptoUtils.js']
      }
    },

    jscs: {
      src: ['lib/*.js', 'Gruntfile.js', 'test/*.js'],
      options: {
        preset: 'airbnb',
        disallowMultipleVarDecl: false,
        requireTrailingComma: false,
      },
      fix: {
        src: ['lib/*.js', 'Gruntfile.js', 'test/*.js'],
        options:{
          preset: 'airbnb',
          disallowMultipleVarDecl: false,
          requireTrailingComma: false,
          fix: true
        }
      }
    }

  });

  grunt.loadNpmTasks('grunt-buddyjs');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-shell');
  grunt.loadNpmTasks('grunt-jscs');

  grunt.registerTask('npmupdate', ['shell:npmupdate']);
  grunt.registerTask('pp', ['jshint', 'jscs', 'buddyjs']);
  grunt.registerTask('test', ['pp', 'mochaTest:unitTest']);

  grunt.registerTask('buildTestCode', ['test']);

  // target to release
  grunt.registerTask('release', ['npmupdate', 'buildTestCode']);

  // codeship target
  grunt.registerTask('codeship', ['npmupdate', 'pp', 'mochaTest:codeshipTest']);

  grunt.registerTask('default', ['npmupdate', 'buildTestCode']);

};
