## How to Write `dependency.json`

### `FLOW_IMPLY_THREATS` Type

- Corresponds to the **Flow-type rules** in the sheet.
- The `"when"` key corresponds to the **if** column in the sheet.
- The `"then"` key corresponds to the **mapping** column, column D, in the sheet.
- The `"op"` key can have only one of the following values: `AND`, `OR`, or `-`.
  - If only a single threat is mapped, such as in rows 8, 9, and 10, use `-`.

### `PRE_THREAT_ENABLES_POST_THREAT` Type

- Corresponds to the **Pre-Post-type rules** in the sheet.
- The `"when"` key corresponds to the **if** column in the sheet.
- The `"then"` key corresponds to the **mapping** column in the sheet.
- The `"op"` key can have only one of the following values: `AND`, `OR`, or `-`.
  - If only a single threat is mapped, such as the value in the mapping column of row 25 or the values in the if column of rows 20, 21, and 22, use `-`.

### `TARGET_ASSET_FORBIDS_THREATS` Type

- Corresponds to the **Not Mapping-Goal-type rules** in the sheet.
- The `"when"` key corresponds to the **if** column in the sheet.
- The `"then"` key corresponds to the **mapping** column in the sheet.
- The `"op"` key can have only one of the following values: `AND`, `OR`, or `-`.
  - Since all rules of this type represent a single target asset to single threat relationship, use `-` for `"op"`.

### `THREAT_FORBIDS_THREATS` Type

- The `"when"` key corresponds to the **if** column in the sheet.
- The `"then"` key corresponds to the **mapping** column in the sheet.
- The `"op"` key can have only one of the following values: `AND`, `OR`, or `-`.
  - In all rules of this type, the values in the mapping column are connected with `AND`; therefore, `"op"` should always be set to `AND`.
