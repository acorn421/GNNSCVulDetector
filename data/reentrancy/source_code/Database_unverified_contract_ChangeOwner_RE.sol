/*
 * ===== SmartInject Injection Details =====
 * Function      : ChangeOwner
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Update**: Introduced a call to `new_owner.call()` that executes before updating the `m_Owner` state variable.
 * 
 * 2. **Callback Mechanism**: The external call invokes `onOwnershipChange()` on the new owner's address, allowing the new owner to execute arbitrary code during the ownership transition.
 * 
 * 3. **State Update After External Call**: The critical state update `m_Owner = new_owner` now happens after the external call, creating a reentrancy window.
 * 
 * 4. **Realistic Justification**: The code appears to "notify" the new owner about the ownership change, which is a common pattern in administrative functions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract with an `onOwnershipChange()` function
 * - Current owner calls `ChangeOwner()` with the malicious contract as the new owner
 * - The malicious contract's `onOwnershipChange()` callback is triggered
 * - At this point, `m_Owner` is still the old owner, but the new owner (attacker) can execute code
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Inside the `onOwnershipChange()` callback, the attacker can:
 *   - Call other administrative functions that still see the old owner as valid
 *   - Manipulate trusted contracts mapping via `ChangeAddressTrust()`
 *   - Transfer funds using `TransferFunds()` before ownership officially changes
 *   - Set up additional malicious contracts as trusted
 * 
 * **Transaction 3 - State Persistence:**
 * - After the callback completes, `m_Owner` is finally updated to the attacker's address
 * - The attacker now has permanent ownership plus any additional privileges gained during the reentrancy window
 * - The accumulated state changes from Transaction 2 persist and compound the attack
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the attacker to first gain callback access (Transaction 1), then exploit the intermediate state (Transaction 2), and finally consolidate control (Transaction 3).
 * 
 * 2. **Persistent State Changes**: Each transaction builds upon the previous one - the callback setup enables the exploitation, which enables the final takeover.
 * 
 * 3. **Cross-Function Dependencies**: The reentrancy window allows manipulation of other contract functions that depend on the ownership state, creating cascading effects across multiple transactions.
 * 
 * 4. **Cannot Be Atomic**: The vulnerability cannot be exploited in a single transaction because it requires the external call to be initiated by a legitimate owner, creating a multi-step process where each step depends on the persistent state from previous steps.
 * 
 * The vulnerability is particularly dangerous because it maintains the appearance of proper access control while creating a window for privilege escalation during ownership transitions.
 */
pragma solidity ^0.4.13;

contract Database
{
    address public m_Owner;
    address public m_Owner2;
    address public m_Creator;
    AbstractRandom m_RandomGen = AbstractRandom(0x3936fba4dc8cf1e2746423a04f5c6b4ade033e81);
    BitGuildToken public tokenContract = BitGuildToken(0x7E43581b19ab509BCF9397a2eFd1ab10233f27dE); // Predefined PLAT token address
    mapping(address => mapping(uint256 => mapping(uint256 => bytes32))) public m_Data;
    mapping(address => bool)  public trustedContracts;

    modifier OnlyOwnerAndContracts()
    {
        require(msg.sender == m_Owner || msg.sender == m_Owner2 || msg.sender== m_Creator || trustedContracts[msg.sender]);
        _;
    }

    function ChangeRandomGen(address rg) public OnlyOwnerAndContracts(){
        m_RandomGen = AbstractRandom(rg);
    }

    function() public payable
    {

    }

    function Database() public
    {
        m_Owner = address(0);
        m_Owner2 = address(0);
        m_Creator = msg.sender;
    }

    function ChangeOwner(address new_owner) OnlyOwnerAndContracts() public
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
{
    require(msg.sender == m_Owner || msg.sender == m_Creator || msg.sender == m_Owner2);

    // Notify the new owner about the ownership change before updating state
    if (new_owner != address(0)) {
        (bool success, ) = new_owner.call(abi.encodeWithSignature("onOwnershipChange(address)", msg.sender));
        require(success, "Owner notification failed");
    }

    m_Owner = new_owner;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function ChangeOwner2(address new_owner2) OnlyOwnerAndContracts() public
    {
        require(msg.sender == m_Owner || msg.sender == m_Creator || msg.sender == m_Owner2);

        m_Owner2 = new_owner2;
    }

    function ChangeAddressTrust(address contract_address,bool trust_flag) public OnlyOwnerAndContracts()
    {
        trustedContracts[contract_address] = trust_flag;
    }

    function Store(address user, uint256 category, uint256 index, bytes32 data) public OnlyOwnerAndContracts()
    {
        m_Data[user][category][index] = data;
    }

    function Load(address user, uint256 category, uint256 index) public view returns (bytes32)
    {
        return m_Data[user][category][index];
    }

    function TransferFunds(address target, uint256 transfer_amount) public OnlyOwnerAndContracts()
    {
        tokenContract.transfer(target,transfer_amount);
    }

    function getRandom(uint256 _upper, uint8 _seed) public OnlyOwnerAndContracts() returns (uint256 number){
        number = m_RandomGen.random(_upper,_seed);

        return number;
    }
 
    

}
contract BitGuildToken{
    function transfer(address _to, uint256 _value) public;
}
contract AbstractRandom
{
    function random(uint256 upper, uint8 seed) public returns (uint256 number);
}