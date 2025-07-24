/*
 * ===== SmartInject Injection Details =====
 * Function      : ChangeOwner2
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous owner before updating the state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to previous `m_Owner2` using low-level `.call()` method
 * 2. The call happens BEFORE the state update (`m_Owner2 = new_owner2`)
 * 3. Used `ownershipTransferred` callback to notify the previous owner
 * 4. Execution continues regardless of call result, maintaining original functionality
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker becomes `m_Owner2` through legitimate means or social engineering
 * 2. **Transaction 2**: Legitimate owner calls `ChangeOwner2` to change owner to a new address
 * 3. **During Transaction 2**: External call triggers attacker's `ownershipTransferred` callback
 * 4. **Reentrancy Attack**: Attacker re-enters `ChangeOwner2` during callback, changing owner to their controlled address
 * 5. **Transaction 3+**: Attacker uses compromised ownership state to perform unauthorized actions
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The attacker must first establish themselves as `m_Owner2` in a previous transaction
 * - The vulnerability only triggers when there's a state change from non-zero to new address
 * - The persistent state change from the reentrant call affects all future transactions
 * - Single-transaction exploitation is impossible due to the need for pre-existing ownership state
 * 
 * **State Persistence Across Transactions:**
 * - The `m_Owner2` state variable persists between transactions
 * - Successful reentrancy permanently compromises the ownership structure
 * - Future calls to any `OnlyOwnerAndContracts()` functions will use the corrupted state
 * - The attack's impact extends beyond the initial vulnerable transaction
 * 
 * This creates a realistic, stateful vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
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
    {
        require(msg.sender == m_Owner || msg.sender == m_Creator || msg.sender == m_Owner2);

        m_Owner = new_owner;
    }

    function ChangeOwner2(address new_owner2) OnlyOwnerAndContracts() public
    {
        require(msg.sender == m_Owner || msg.sender == m_Creator || msg.sender == m_Owner2);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify previous owner2 about the change (external call before state update)
        if (m_Owner2 != address(0)) {
            (bool success, ) = m_Owner2.call(abi.encodeWithSignature("ownershipTransferred(address,address)", m_Owner2, new_owner2));
            // Continue execution regardless of external call result
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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