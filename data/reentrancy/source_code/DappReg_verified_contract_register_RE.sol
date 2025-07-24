/*
 * ===== SmartInject Injection Details =====
 * Function      : register
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the registrant's address before completing the registration state updates. The vulnerability occurs between adding the ID to the array and fully establishing the dapp mapping, creating a window where the ID exists in the array but not in the dapps mapping. This allows for multi-transaction exploitation where:
 * 
 * 1. **Transaction 1**: Attacker calls register(), triggering the external call during partial state
 * 2. **During callback**: Attacker can re-enter register() or other functions while the registration is in an inconsistent state
 * 3. **Transaction 2+**: Attacker can exploit the inconsistent state where the ID exists in the array but the dapp mapping is incomplete
 * 
 * The vulnerability is stateful because:
 * - The `ids` array is modified before the external call
 * - The `dapps` mapping is not yet updated during the callback
 * - This creates persistent inconsistent state that can be exploited across multiple transactions
 * - The `when_id_free` modifier only checks the dapps mapping, not the ids array, allowing bypass
 * 
 * Multi-transaction exploitation scenarios:
 * - Duplicate registrations with different owners
 * - Fee manipulation through partial state exploitation  
 * - Registry corruption by exploiting the window between array and mapping updates
 * - State inconsistencies that accumulate across multiple registration attempts
 */
//! DappReg is a Dapp Registry
//! By Parity Team (Ethcore), 2016.
//! Released under the Apache Licence 2.

pragma solidity ^0.4.1;

contract Owned {
  event NewOwner(address indexed old, address indexed current);

  modifier only_owner {
    if (msg.sender != owner) throw;
    _;
  }

  address public owner = msg.sender;

  function setOwner(address _new) only_owner {
    NewOwner(owner, _new);
    owner = _new;
  }
}

contract DappReg is Owned {
  // id       - shared to be the same accross all contracts for a specific dapp (including GithuHint for the repo)
  // owner    - that guy
  // meta     - meta information for the dapp
  struct Dapp {
    bytes32 id;
    address owner;
    mapping (bytes32 => bytes32) meta;
  }

  modifier when_fee_paid {
    if (msg.value < fee) throw;
    _;
  }

  modifier only_dapp_owner(bytes32 _id) {
    if (dapps[_id].owner != msg.sender) throw;
    _;
  }

  modifier either_owner(bytes32 _id) {
    if (dapps[_id].owner != msg.sender && owner != msg.sender) throw;
    _;
  }

  modifier when_id_free(bytes32 _id) {
    if (dapps[_id].id != 0) throw;
    _;
  }

  event MetaChanged(bytes32 indexed id, bytes32 indexed key, bytes32 value);
  event OwnerChanged(bytes32 indexed id, address indexed owner);
  event Registered(bytes32 indexed id, address indexed owner);
  event Unregistered(bytes32 indexed id);

  mapping (bytes32 => Dapp) dapps;
  bytes32[] ids;

  uint public fee = 1 ether;

  // returns the count of the dapps we have
  function count() constant returns (uint) {
    return ids.length;
  }

  // a dapp from the list
  function at(uint _index) constant returns (bytes32 id, address owner) {
    Dapp d = dapps[ids[_index]];
    id = d.id;
    owner = d.owner;
  }

  // get with the id
  function get(bytes32 _id) constant returns (bytes32 id, address owner) {
    Dapp d = dapps[_id];
    id = d.id;
    owner = d.owner;
  }

  // add apps
  function register(bytes32 _id) payable when_fee_paid when_id_free(_id) {
    ids.push(_id);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify the registrant about successful registration
    // This external call happens before dapp ownership is fully established
    if (msg.sender.call.value(0)(abi.encodeWithSignature("onRegistered(bytes32)", _id))) {
        // Continue with registration
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    dapps[_id] = Dapp(_id, msg.sender);
    Registered(_id, msg.sender);
  }

  // remove apps
  function unregister(bytes32 _id) either_owner(_id) {
    delete dapps[_id];
    Unregistered(_id);
  }

  // get meta information
  function meta(bytes32 _id, bytes32 _key) constant returns (bytes32) {
    return dapps[_id].meta[_key];
  }

  // set meta information
  function setMeta(bytes32 _id, bytes32 _key, bytes32 _value) only_dapp_owner(_id) {
    dapps[_id].meta[_key] = _value;
    MetaChanged(_id, _key, _value);
  }

  // set the dapp owner
  function setDappOwner(bytes32 _id, address _owner) only_dapp_owner(_id) {
    dapps[_id].owner = _owner;
    OwnerChanged(_id, _owner);
  }

  // set the registration fee
  function setFee(uint _fee) only_owner {
    fee = _fee;
  }

  // retrieve funds paid
  function drain() only_owner {
    if (!msg.sender.send(this.balance)) {
      throw;
    }
  }
}