## INTRODUCTION

The digitalia_muni_group_permissions module extends permission system of group module. Node access is determined by value in `field_access_rights`, media access is determined by value in `field_access_rights` of node referenced in `field_media_of`.


## REQUIREMENTS

drupal/group
Two fields
- field_access_rights - type select list, with choices `embargoed_access`, `metadata_only_access`, `open_access`, `restricted_access`, `restricted_metadata_only_access`
- field_embargo_end_date - type Date

## INSTALLATION

Install as you would normally install a contributed Drupal module.
See: https://www.drupal.org/node/895232 for further information.

## CONFIGURATION

In group permission config, add desired permissions to users. This functions for direct access to enties only, for expected views functionality a [patch](https://github.com/ArtsFacultyMU/digitalia-patches/blob/main/EntityQueryAlter.patch) for group module is needed.


