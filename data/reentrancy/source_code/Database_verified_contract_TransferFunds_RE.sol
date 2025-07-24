/*
 * ===== SmartInject Injection Details =====
 * Function      : TransferFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **State Variables**: Added `pendingTransfers` mapping to track accumulated transfer amounts per target, and `transferInProgress` flag to track transfer status.
 * 
 * 2. **Multi-Transaction Logic**: The function now requires at least 2 calls to the same target to trigger the actual transfer. First call accumulates the amount, second call processes it.
 * 
 * 3. **Reentrancy Vulnerability**: On the second call, the function makes the external `tokenContract.transfer()` call BEFORE updating the `pendingTransfers[target] = 0` state, violating the Checks-Effects-Interactions pattern.
 * 
 * 4. **Exploitation Scenario**: 
 *    - Transaction 1: Call `TransferFunds(maliciousContract, 100)` - sets `pendingTransfers[maliciousContract] = 100`
 *    - Transaction 2: Call `TransferFunds(maliciousContract, 50)` - triggers transfer of 150 tokens
 *    - During the `tokenContract.transfer()` call, if `maliciousContract` has a fallback/receive function, it can re-enter `TransferFunds` again
 *    - Since `pendingTransfers[maliciousContract]` is still 100 (not yet reset), the malicious contract can exploit this to drain more tokens
 * 
 * 5. **Multi-Transaction Requirement**: The vulnerability only manifests when there are accumulated pending transfers from previous transactions, making it impossible to exploit in a single atomic transaction.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingTransfers;
    mapping(address => bool) public transferInProgress;
    
    function TransferFunds(address target, uint256 transfer_amount) public OnlyOwnerAndContracts()
    {
        // Check if there's already a pending transfer for this target
        if (pendingTransfers[target] > 0) {
            // Process accumulated pending transfer
            uint256 totalAmount = pendingTransfers[target] + transfer_amount;
            
            // Mark transfer as in progress
            transferInProgress[target] = true;
            
            // External call before state update - VULNERABILITY
            tokenContract.transfer(target, totalAmount);
            
            // State update after external call - allows reentrancy
            pendingTransfers[target] = 0;
            transferInProgress[target] = false;
        } else {
            // First transfer - accumulate in pending state
            pendingTransfers[target] = transfer_amount;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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