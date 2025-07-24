/*
 * ===== SmartInject Injection Details =====
 * Function      : ChangeOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-based cooldown mechanism that creates a multi-transaction vulnerability. The vulnerability allows miners to manipulate block timestamps to bypass security restrictions. In Transaction 1, an attacker initiates an ownership change which sets m_LastOwnerChangeTime. In Transaction 2 (within the same block or by manipulating future block timestamps), the attacker can bypass the 24-hour cooldown by exploiting the miner's ability to manipulate block.timestamp within reasonable bounds. The emergency bypass window (first hour) also creates additional timestamp manipulation opportunities. This requires multiple transactions because: (1) the cooldown state must be established in a prior transaction, (2) the timestamp manipulation must occur in subsequent transactions, and (3) the actual exploitation happens across multiple blocks where miners can influence timestamps.
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
    uint256 public m_LastOwnerChangeTime; // **Added declaration**

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
        m_LastOwnerChangeTime = now; // Initialize to deployment time for timestamp logic
    }

    function ChangeOwner(address new_owner) OnlyOwnerAndContracts() public
    {
        require(msg.sender == m_Owner || msg.sender == m_Creator || msg.sender == m_Owner2);

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based protection to prevent rapid ownership changes
        // Normal ownership changes require a 24-hour cooldown period
        // Emergency ownership changes (within 1 hour of deployment) can bypass cooldown
        if (block.timestamp > 3600) { // After 1 hour from deployment
            require(block.timestamp >= m_LastOwnerChangeTime + 86400); // Removed error string for compatibility
        }

        m_Owner = new_owner;
        m_LastOwnerChangeTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
