<?php

namespace Drupal\digitalia_muni_group_permissions\Plugin\Group\RelationHandler;

use Drupal\group\Plugin\Group\RelationHandler\PermissionProviderInterface;
use Drupal\group\Plugin\Group\RelationHandler\PermissionProviderTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;

class DMPermissionProvider implements PermissionProviderInterface {
  use PermissionProviderTrait;

  protected $entityFieldManager;

  public static function create(ContainerInterface $container) {
    $instance = new static();
    $instance->setEntityFieldManager($container->get('entity_field.manager'));
    return $instance;
  }

  public function setEntityFieldManager(EntityFieldManagerInterface $entityFieldManager): self {
    $this->entityFieldManager = $entityFieldManager;
    return $this;
  }

  public function groupPermissions() {
    $perms = [];

    // TODO: Implement as a service? Config? From field definition?
    $access_rights = [
      "embargoed_access" => "embargoed access",
      "metadata_only_access" => "metadata only access",
      "open_access" => "open access",
      "restricted_access" => "restricted access",
      "restricted_metadata_only_access" => "restricted metadata only access",
    ];

    foreach ($access_rights as $field => $label) {
      foreach (["published", "unpublished"] as $status) {
        $perms["view any {$status} {$field}"] = [
          'title' => 'View any @status @fieldname items',
          'title_args' => [
            '@fieldname' => $label,
            '@status' => $status,
          ]
        ];
      }
    }

    return $perms;
  }
}
