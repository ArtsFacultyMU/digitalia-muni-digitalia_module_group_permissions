<?php

namespace Drupal\digitalia_muni_group_permissions\Plugin\Group\RelationHandler;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultNeutral;
use Drupal\Core\Session\AccountInterface;
use Drupal\group\Plugin\Group\RelationHandler\AccessControlInterface;
use Drupal\group\Plugin\Group\RelationHandler\AccessControlTrait;
use Drupal\user\EntityOwnerInterface;

class DMNodeAccessControl implements AccessControlInterface {
  use AccessControlTrait;

  /**
   * Constructs a new DMNodeAccessControl.
   *
   * @param \Drupal\group\Plugin\Group\RelationHandler\AccessControlInterface $parent
   *   The parent access control handler.
   */
  public function __construct(AccessControlInterface $parent) {
    $this->parent = $parent;
  }
  
  public function entityAccess(EntityInterface $entity, $operation, AccountInterface $account, $return_as_object = FALSE) {
    $parent_access = $this->parent->entityAccess($entity, $operation, $account, $return_as_object);

    if ($this->supportsOperation($operation, "entity") === FALSE) {
      return $parent_access;
    }

    $storage = $this->entityTypeManager->getStorage('group_relationship');
    $groupRelationships = $storage->loadByEntity($entity);
    if (empty($groupRelationships)) {
      // If the entity does not belong to any group, we have nothing to say.
      return $parent_access;
    }

    // does the entity have field_access_rights?
    if (!$entity->hasField("field_access_rights") || $operation != "view") {
      return $parent_access;
    }

    $status = $entity->get("status")->value;
    $is_published = $entity->isPublished();
    $access_rights = $entity->get("field_access_rights")->value;
    
    $access = AccessResultNeutral::neutral();

    /** @var \Drupal\group\Entity\GroupRelationship $groupRelationship */
    foreach ($groupRelationships as $groupRelationship) {
      $group = $groupRelationship->getGroup();

      // Anyone if published AND embargo passed, allowed roles if unpublished (regardless of embargo date)
      if ($access_rights == "embargoed_access") {
        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any published $access_rights", $account)
          && $is_published
          && $entity->hasField("field_embargo_end_date")
          && strtotime($entity->get("field_embargo_end_date")->value) < time()
        ));

        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any unpublished $access_rights", $account)
        ));
      }

      // Anyone if published, allowed roles if unpublished
      if ($access_rights == "metadata_only_access") {
        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any published $access_rights", $account)
          && $is_published
        ));

        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any unpublished $access_rights", $account)
          && !$is_published
        ));
      }

      // Anyone if published, allowed roles if unpublished
      if ($access_rights == "open_access") {
        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any published $access_rights", $account)
          && $is_published
        ));

        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any unpublished $access_rights", $account)
          && !$is_published
        ));
      }

      // Only allowed roles even if published
      if ($access_rights == "restricted_access") {
        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any published $access_rights", $account)
          && $is_published
        ));

        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any unpublished $access_rights", $account)
          && !$is_published
        ));
      }

      // Only allowed roles even if published, only metadata
      if ($access_rights == "restricted_metadata_only_access") {
        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any published $access_rights", $account)
          && $is_published
        ));

        $access = $access->orIf(AccessResult::allowedIf(
          $group->hasPermission("$operation any unpublished $access_rights", $account)
          && !$is_published
        ));
      }

      $owner_access = AccessResultNeutral::neutral()->orIf(AccessResult::allowedIf(
        $entity instanceof EntityOwnerInterface
        && $entity->getOwnerId() === $account->id()
      ));

      $access = $access->orIf($owner_access);
      $access->addCacheableDependency($groupRelationship);
      $access->addCacheableDependency($group);
    }

    // Leave it to parent if we can't say
    if ($access->isNeutral()) {
      $access = $parent_access;
    }
    
    return $access;
  }
}
