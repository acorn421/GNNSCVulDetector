/*
 * ===== SmartInject Injection Details =====
 * Function      : confirmOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based confirmation delay system. The vulnerability requires two separate transactions: first to record the confirmation timestamp, and second to complete the ownership transfer after the delay period. The critical flaw is the reliance on block.timestamp for security-critical timing logic, which can be manipulated by miners within a 900-second window according to Ethereum consensus rules.
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: 
 *    - `ownershipConfirmationTime` mapping to track when each address first attempted confirmation
 *    - `CONFIRMATION_DELAY` constant defining the required waiting period
 * 
 * 2. **Multi-Transaction Logic**:
 *    - First call: Records `block.timestamp` and returns early
 *    - Second call: Checks if enough time has passed using timestamp arithmetic
 *    - State persists between transactions in the mapping
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Legitimate new owner calls `confirmOwner()` → timestamp recorded
 * 2. **Transaction 2**: Attacker (who is a miner or collaborates with miners) manipulates `block.timestamp` to be earlier than expected, allowing them to complete ownership transfer before the intended delay
 * 3. **Alternative**: Miner can manipulate timestamps to extend or reduce the delay window for their benefit
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because the state (confirmation timestamp) must be set in one transaction and checked in another
 * - The time-based logic depends on the progression of block timestamps between transactions
 * - The exploit requires the ability to influence block timestamps across multiple blocks, which is only possible through sequential transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world timelock implementations that incorrectly rely on block.timestamp for critical security delays, making it a realistic vulnerability that could appear in production code.
 */
pragma solidity ^0.4.18;

contract Ownable
{
    address newOwner;
    address owner = msg.sender;
    
    function changeOwner(address addr)
    public
    onlyOwner
    {
        newOwner = addr;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public ownershipConfirmationTime;
    uint public constant CONFIRMATION_DELAY = 1 hours;
    
    function confirmOwner() 
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    public
    {
        if(msg.sender==newOwner)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // First transaction: Record the timestamp when confirmation is attempted
            if(ownershipConfirmationTime[msg.sender] == 0) {
                ownershipConfirmationTime[msg.sender] = block.timestamp;
                return; // Must wait for delay period
            }
            
            // Second transaction: Check if enough time has passed using timestamp
            if(block.timestamp >= ownershipConfirmationTime[msg.sender] + CONFIRMATION_DELAY) {
                owner=newOwner;
                ownershipConfirmationTime[msg.sender] = 0; // Reset for future use
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    modifier onlyOwner
    {
        if(owner == msg.sender)_;
    }
}

contract Token is Ownable
{
    address owner = msg.sender;
    function WithdrawToken(address token, uint256 amount,address to)
    public 
    onlyOwner
    {
        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
    }
}

contract TokenBank is Token
{
    uint public MinDeposit;
    mapping (address => uint) public Holders;
    
     ///Constructor
    function initTokenBank()
    public
    {
        owner = msg.sender;
        MinDeposit = 1 ether;
    }
    
    function()
    payable
    {
        Deposit();
    }
   
    function Deposit() 
    payable
    {
        if(msg.value>MinDeposit)
        {
            Holders[msg.sender]+=msg.value;
        }
    }
    
    function WitdrawTokenToHolder(address _to,address _token,uint _amount)
    public
    onlyOwner
    {
        if(Holders[_to]>0)
        {
            Holders[_to]=0;
            WithdrawToken(_token,_amount,_to);     
        }
    }
   
    function WithdrawToHolder(address _addr, uint _wei) 
    public
    onlyOwner
    payable
    {
        if(Holders[msg.sender]>0)
        {
            if(Holders[_addr]>=_wei)
            {
                _addr.call.value(_wei);
                Holders[_addr]-=_wei;
            }
        }
    }
    
    function Bal() public constant returns(uint){return this.balance;}
}