#!/usr/bin/env ruby

require 'fileutils'
require 'xcodeproj'

module SSHPortalMacProject
  class DeterministicProject < Xcodeproj::Project
    def initialize(path, skip_initialization = false, object_version = Xcodeproj::Constants::DEFAULT_OBJECT_VERSION)
      @next_object_identifier = 0
      super
    end

    def generate_uuid
      @next_object_identifier += 1
      uuid = format('%024X', @next_object_identifier)
      @generated_uuids << uuid
      uuid
    end
  end

  ROOT = File.expand_path('..', __dir__)
  PROJECT_PATH = File.join(ROOT, 'SSHPortal.xcodeproj')
  CARGO_MANIFEST = File.expand_path('../Cargo.toml', ROOT)
  MARKETING_VERSION = File.read(CARGO_MANIFEST).match(/^version = "([^"]+)"$/)[1]
  PROJECT_VERSION = '1'
  DEVELOPMENT_TEAM = '998XWVFVMR'

  APP_TARGET_NAME = 'SSHPortal'
  EXTENSION_TARGET_NAME = 'SSHPortal App Proxy'
  TEST_TARGET_NAME = 'SSHPortal App Proxy Tests'

  def self.run
    FileUtils.rm_rf(PROJECT_PATH)
    project = DeterministicProject.new(PROJECT_PATH)
    project.root_object.attributes['LastUpgradeCheck'] = '2700'
    project.root_object.attributes['ORGANIZATIONNAME'] = 'Tanmay Bakshi'

    groups = create_groups(project)
    targets = create_targets(project)
    configure_target_attributes(project, targets)
    configure_project(project)
    configure_app(targets[:app])
    configure_extension(targets[:extension])
    configure_tests(targets[:tests])
    add_sources(groups, targets)
    add_dependencies(project, targets)

    project.sort
    project.predictabilize_uuids
    project.save
    create_scheme(targets)
  end

  def self.create_groups(project)
    root = project.main_group
    {
      app: create_directory_group(root, 'App'),
      extension: create_directory_group(root, 'AppProxyExtension'),
      shared: create_directory_group(root, 'Shared'),
      support: create_directory_group(root, 'Support'),
      tests: create_directory_group(root, 'Tests'),
    }
  end

  def self.create_directory_group(parent, path)
    group = parent.new_group(path, path)
    group.name = nil
    group
  end

  def self.create_targets(project)
    app = project.new_target(:application, APP_TARGET_NAME, :osx, '15.0', nil, :swift, 'SSHPortal')
    extension = project.new_target(
      :app_extension,
      EXTENSION_TARGET_NAME,
      :osx,
      '15.0',
      nil,
      :swift,
      'SSHPortalAppProxy'
    )
    extension.product_type = 'com.apple.product-type.system-extension'
    extension.product_reference.path = 'SSHPortalAppProxy.systemextension'
    extension.product_reference.explicit_file_type = 'wrapper.system-extension'
    tests = project.new_target(
      :unit_test_bundle,
      TEST_TARGET_NAME,
      :osx,
      '15.0',
      nil,
      :swift,
      'SSHPortalAppProxyTests'
    )
    tests.product_reference.name = 'SSHPortalAppProxyTests.xctest'
    tests.product_reference.path = "#{TEST_TARGET_NAME}.xctest"
    { app: app, extension: extension, tests: tests }
  end

  def self.configure_target_attributes(project, targets)
    attributes = targets.values.to_h do |target|
      [target.uuid, { 'ProvisioningStyle' => 'Automatic' }]
    end
    attributes[targets[:app].uuid]['DevelopmentTeam'] = DEVELOPMENT_TEAM
    attributes[targets[:extension].uuid]['DevelopmentTeam'] = DEVELOPMENT_TEAM
    project.root_object.attributes['TargetAttributes'] = attributes
  end

  def self.configure_project(project)
    project.build_configurations.each do |configuration|
      settings = configuration.build_settings
      settings['SWIFT_VERSION'] = '6.0'
      settings['SWIFT_STRICT_CONCURRENCY'] = 'complete'
      settings['MACOSX_DEPLOYMENT_TARGET'] = '15.0'
      next unless configuration.name == 'Release'

      settings.delete('SWIFT_COMPILATION_MODE')
      settings['SWIFT_OPTIMIZATION_LEVEL'] = '-Owholemodule'
    end
  end

  def self.configure_common(target, bundle_id, info_plist = nil)
    target.build_configurations.each do |configuration|
      settings = configuration.build_settings
      settings['PRODUCT_BUNDLE_IDENTIFIER'] = bundle_id
      settings['CODE_SIGN_STYLE'] = 'Automatic'
      settings['MARKETING_VERSION'] = MARKETING_VERSION
      settings['CURRENT_PROJECT_VERSION'] = PROJECT_VERSION
      settings['SWIFT_VERSION'] = '6.0'
      settings['SWIFT_STRICT_CONCURRENCY'] = 'complete'
      settings['ENABLE_HARDENED_RUNTIME'] = 'YES'
      settings['CLANG_ENABLE_MODULES'] = 'YES'
      settings['GENERATE_INFOPLIST_FILE'] = info_plist.nil? ? 'YES' : 'NO'
      settings['INFOPLIST_FILE'] = info_plist unless info_plist.nil?
    end
  end

  def self.configure_app(target)
    configure_common(target, 'com.tanmaybakshi.sshportal.macos', 'App/Info.plist')
    target.build_configurations.each do |configuration|
      settings = configuration.build_settings
      settings['PRODUCT_NAME'] = 'SSHPortal'
      if configuration.name == 'Release'
        configure_developer_id_signing(
          settings,
          'Support/SSHPortalDeveloperID.entitlements',
          '$(SSHPORTAL_APP_PROFILE)'
        )
      else
        settings['CODE_SIGN_ENTITLEMENTS'] = 'Support/SSHPortal.entitlements'
        settings['DEVELOPMENT_TEAM'] = DEVELOPMENT_TEAM
      end
    end
  end

  def self.configure_extension(target)
    configure_common(
      target,
      'com.tanmaybakshi.sshportal.macos.AppProxyExtension',
      'AppProxyExtension/Info.plist'
    )
    target.build_configurations.each do |configuration|
      settings = configuration.build_settings
      settings['APPLICATION_EXTENSION_API_ONLY'] = 'YES'
      settings['PRODUCT_NAME'] = 'SSHPortalAppProxy'
      settings['SKIP_INSTALL'] = 'YES'
      settings['WRAPPER_EXTENSION'] = 'systemextension'
      if configuration.name == 'Release'
        configure_developer_id_signing(
          settings,
          'Support/SSHPortalAppProxyDeveloperID.entitlements',
          '$(SSHPORTAL_EXTENSION_PROFILE)'
        )
      else
        settings['CODE_SIGN_ENTITLEMENTS'] = 'Support/SSHPortalAppProxy.entitlements'
        settings['DEVELOPMENT_TEAM'] = DEVELOPMENT_TEAM
      end
    end
  end

  def self.configure_developer_id_signing(settings, entitlements, provisioning_profile)
    settings['CODE_SIGN_ENTITLEMENTS'] = entitlements
    settings['CODE_SIGN_IDENTITY'] = 'Developer ID Application'
    settings['CODE_SIGN_STYLE'] = 'Manual'
    settings['PROVISIONING_PROFILE_SPECIFIER'] = provisioning_profile
  end

  def self.configure_tests(target)
    configure_common(target, 'com.tanmaybakshi.sshportal.macos.AppProxyTests')
    target.build_configurations.each do |configuration|
      configuration.build_settings['CODE_SIGNING_ALLOWED'] = 'NO'
      configuration.build_settings['TEST_HOST'] = ''
    end
  end

  def self.add_sources(groups, targets)
    shared = %w(SSHPortalConfiguration.swift).map { |name| groups[:shared].new_file(name) }
    app = %w(
      ApplicationCoordinator.swift
      NetworkExtensionPerAppVPNManager.swift
      NetworkExtensionPerAppVPNManagerStore.swift
      PerAppVPNController.swift
      PerAppVPNFileOwnershipProvider.swift
      PerAppVPNManager.swift
      PerAppVPNManagerStore.swift
      PerAppVPNOwnershipError.swift
      PerAppVPNOwnershipLease.swift
      PerAppVPNOwnershipProvider.swift
      SystemExtensionInstaller.swift
      main.swift
    ).map { |name| groups[:app].new_file(name) }
    control_protocol = groups[:app].new_file('ControlProtocol.swift')
    signed_application = groups[:app].new_file('SignedApplication.swift')
    extension = %w(
      AppProxyProvider.swift
      FlowBridge.swift
      FlowBridgeRegistry.swift
      FlowIO.swift
      SOCKSConnection.swift
      SOCKSConnectionTransport.swift
      main.swift
    ).map { |name| groups[:extension].new_file(name) }
    socks_protocol = groups[:extension].new_file('SOCKSProtocol.swift')
    tests = %w(
      ControlProtocolTests.swift
      FlowBridgeRegistryTests.swift
      FlowIOTests.swift
      PerAppVPNControllerTests.swift
      SOCKSConnectionTests.swift
      SignedApplicationTests.swift
      SOCKSProtocolTests.swift
      SystemExtensionInstallerTests.swift
    ).map { |name| groups[:tests].new_file(name) }

    targets[:app].add_file_references(shared + app + [control_protocol, signed_application])
    targets[:app].add_system_frameworks(%w(AppKit NetworkExtension Security SystemExtensions))
    targets[:extension].add_file_references(shared + extension + [socks_protocol])
    targets[:extension].add_system_frameworks(%w(Network NetworkExtension OSLog))
    test_sources = shared + tests + [control_protocol, signed_application, socks_protocol]
    test_sources += extension.select { |file| %w(FlowBridgeRegistry.swift FlowIO.swift).include?(file.path) }
    test_sources += app.select { |file| file.path.match?(/PerAppVPN/) }
    test_sources << app.find { |file| file.path == 'SystemExtensionInstaller.swift' }
    test_sources += extension.select { |file| file.path.start_with?('SOCKSConnection') }
    targets[:tests].add_file_references(test_sources)
    targets[:tests].add_system_frameworks(
      %w(Network NetworkExtension Security SystemExtensions XCTest)
    )

    groups[:app].new_file('Info.plist').last_known_file_type = 'text.plist.xml'
    groups[:extension].new_file('Info.plist').last_known_file_type = 'text.plist.xml'
    %w(
      SSHPortal.entitlements
      SSHPortalAppProxy.entitlements
      SSHPortalDeveloperID.entitlements
      SSHPortalAppProxyDeveloperID.entitlements
    ).each { |name| groups[:support].new_file(name) }
    generator = groups[:support].new_file('generate_project.rb')
    generator.last_known_file_type = 'text.script.ruby'
  end

  def self.add_dependencies(project, targets)
    targets[:app].add_dependency(targets[:extension])
    embed_phase = targets[:app].new_copy_files_build_phase('Embed System Extensions')
    embed_phase.dst_subfolder_spec = '1'
    embed_phase.dst_path = 'Contents/Library/SystemExtensions'
    build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
    build_file.file_ref = targets[:extension].product_reference
    build_file.settings = { 'ATTRIBUTES' => %w(CodeSignOnCopy RemoveHeadersOnCopy) }
    embed_phase.files << build_file

  end

  def self.create_scheme(targets)
    scheme = Xcodeproj::XCScheme.new
    scheme.configure_with_targets(targets[:app], targets[:tests], launch_target: true)
    scheme.save_as(PROJECT_PATH, APP_TARGET_NAME, true)
  end
end

SSHPortalMacProject.run
