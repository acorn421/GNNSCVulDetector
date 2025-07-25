/*
 * ===== SmartInject Injection Details =====
 * Function      : updatefee
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a sophisticated multi-transaction timestamp dependence vulnerability with the following components:
 * 
 * 1. **Time-Based Fee Adjustments**: Added logic that applies bonuses/penalties based on time elapsed since last update, creating predictable timestamp-dependent behavior.
 * 
 * 2. **Emergency Window Exploitation**: Implemented a daily "emergency window" (first hour of each day) that allows bypassing the 10% fee increase limit, enabling up to 50% increases during specific timestamp ranges.
 * 
 * 3. **Timestamp-Based Interval Randomization**: Added pseudo-randomization to the fee change interval using block.timestamp modulo operations, creating predictable patterns that can be exploited.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1**: Owner calls updatefee() during non-emergency hours with a moderate fee increase, establishing the feeChangeInterval baseline.
 * 
 * **Transaction 2**: After waiting for the appropriate time window, owner calls updatefee() again during the emergency window (first hour of day) with a much higher fee (up to 50% increase instead of 10%).
 * 
 * **Transaction 3**: Repeat the process, accumulating fee increases over multiple cycles by timing transactions to exploit the emergency window.
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: Each fee update modifies the serviceFee and feeChangeInterval state variables, creating a history that affects future calculations.
 * 
 * 2. **Time-Window Dependency**: The emergency window only occurs during specific daily time periods, requiring multiple transactions timed across different timestamp ranges.
 * 
 * 3. **Cooldown Period**: The mandatory 1-day cooldown between updates forces exploitation to occur across multiple transactions over time.
 * 
 * 4. **Compound Effects**: The time-based adjustments and emergency windows create opportunities for compound exploitation that only becomes effective through repeated interactions.
 * 
 * Miners or attackers with timestamp manipulation capabilities can exploit this by timing their transactions to coincide with favorable timestamp conditions, allowing them to bypass fee increase limits and accumulate larger fee changes than intended.
 */
pragma solidity ^0.4.24; 

/* ----------------------------------------------------------------------------
 Client contract.
 This contract is generated for each user (user account). All the transactions of a user are executed from this contract.
 Only Aion smart contract can interact with the user account and only when the user schedules transactions.
 ----------------------------------------------------------------------------*/

contract AionClient {
    
    address private AionAddress;

    constructor(address addraion) public{
        AionAddress = addraion;
    }

    
    function execfunct(address to, uint256 value, uint256 gaslimit, bytes data) external returns(bool) {
        require(msg.sender == AionAddress);
        return to.call.value(value).gas(gaslimit)(data);

    }
    

    function () payable public {}

}


// ----------------------------------------------------------------------------
// SafeMat library
// ----------------------------------------------------------------------------
library SafeMath {
  /** @dev Multiplies two numbers, throws on overflow.*/
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {return 0;}
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }

  /** @dev Integer division of two numbers, truncating the quotient.*/
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

  /**@dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).*/
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }

  /** @dev Adds two numbers, throws on overflow.*/
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }

}



/* ----------------------------------------------------------------------------
 Aion Smart contract (by ETH-Pantheon)
  ----------------------------------------------------------------------------*/

contract Aion {
    using SafeMath for uint256;

    address public owner;
    uint256 public serviceFee;
    uint256 public AionID;
    uint256 public feeChangeInterval;
    mapping(address => address) public clientAccount;
    mapping(uint256 => bytes32) public scheduledCalls;

    // Log for executed transactions.
    event ExecutedCallEvent(address indexed from, uint256 indexed AionID, bool TxStatus, bool TxStatus_cancel, bool reimbStatus);
    
    // Log for scheduled transactions.                        
    event ScheduleCallEvent(uint256 indexed blocknumber, address indexed from, address to, uint256 value, uint256 gaslimit,
                            uint256 gasprice, uint256 fee, bytes data, uint256 indexed AionID, bool schedType);
    
    // Log for cancelation of a scheduled call (no fee is charged, all funds are moved from client's smart contract to client's address)                        
    event CancellScheduledTxEvent(address indexed from, uint256 Total, bool Status, uint256 indexed AionID);
    

    // Log for changes in the service fee
    event feeChanged(uint256 newfee, uint256 oldfee);
    

    
    
    constructor () public {
        owner = msg.sender;
        serviceFee = 500000000000000;
    }    

    // This function allows to change the address of the owner (admin of the contract)
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner);
        withdraw();
        owner = newOwner;
    }

    // This function creates an account (contract) for a client if his address is 
    // not yet associated to an account
    function createAccount() internal {
        if(clientAccount[msg.sender]==address(0x0)){
            AionClient newContract = new AionClient(address(this));
            clientAccount[msg.sender] = address(newContract);
        }
    }
    
    
    
    /* This function schedules transactions: client should provide an amount of Ether equal to value + gaslimit*gasprice + serviceFee
    @param blocknumber block or timestamp at which the transaction should be executed. 
    @param to recipient of the transaction.
    @param value Amount of Wei to send with the transaction.
    @param gaslimit maximum amount of gas to spend in the transaction.
    @param gasprice value to pay per unit of gas.
    @param data transaction data.
    @param schedType determines if the transaction is scheduled on blocks or timestamp (true->timestamp)
    @return uint256 Identification of the transaction
    @return address address of the client account created
    */
    function ScheduleCall(uint256 blocknumber, address to, uint256 value, uint256 gaslimit, uint256 gasprice, bytes data, bool schedType) public payable returns (uint,address){
        require(msg.value == value.add(gaslimit.mul(gasprice)).add(serviceFee));
        AionID = AionID + 1;
        scheduledCalls[AionID] = keccak256(abi.encodePacked(blocknumber, msg.sender, to, value, gaslimit, gasprice, serviceFee, data, schedType));
        createAccount();
        clientAccount[msg.sender].transfer(msg.value);
        emit ScheduleCallEvent(blocknumber, msg.sender, to, value, gaslimit, gasprice, serviceFee, data, AionID, schedType);
        return (AionID,clientAccount[msg.sender]);
    }

    
    /* This function executes the transaction at the correct time/block
    Aion off-chain system should provide the correct information for executing a transaction.
    The information is checked against the hash of the original data provided by the user saved in scheduledCalls.
    If the information does not match, the transaction is reverted.
    */
    function executeCall(uint256 blocknumber, address from, address to, uint256 value, uint256 gaslimit, uint256 gasprice,
                         uint256 fee, bytes data, uint256 aionId, bool schedType) external {
        require(msg.sender==owner);
        if(schedType) require(blocknumber <= block.timestamp);
        if(!schedType) require(blocknumber <= block.number);
        
        require(scheduledCalls[aionId]==keccak256(abi.encodePacked(blocknumber, from, to, value, gaslimit, gasprice, fee, data, schedType)));
        AionClient instance = AionClient(clientAccount[from]);
        
        require(instance.execfunct(address(this), gasprice*gaslimit+fee, 2100, hex"00"));
        bool TxStatus = instance.execfunct(to, value, gasleft().sub(50000), data);
        
        // If the user tx fails return the ether to user
        bool TxStatus_cancel;
        if(!TxStatus && value>0){TxStatus_cancel = instance.execfunct(from, value, 2100, hex"00");}
        
        delete scheduledCalls[aionId];
        bool reimbStatus = from.call.value((gasleft()).mul(gasprice)).gas(2100)();
        emit ExecutedCallEvent(from, aionId,TxStatus, TxStatus_cancel, reimbStatus);
        
    }

    
    /* This function allows clients to cancel scheduled transctions. No fee is charged.
    Parameters are the same as in ScheduleCall.
    @return bool indicating success or failure.
    */
    function cancellScheduledTx(uint256 blocknumber, address from, address to, uint256 value, uint256 gaslimit, uint256 gasprice,
                         uint256 fee, bytes data, uint256 aionId, bool schedType) external returns(bool) {
        if(schedType) require(blocknumber >=  block.timestamp+(3 minutes) || blocknumber <= block.timestamp-(5 minutes));
        if(!schedType) require(blocknumber >  block.number+10 || blocknumber <= block.number-20);
        require(scheduledCalls[aionId]==keccak256(abi.encodePacked(blocknumber, from, to, value, gaslimit, gasprice, fee, data, schedType)));
        require(msg.sender==from);
        AionClient instance = AionClient(clientAccount[msg.sender]);
        
        bool Status = instance.execfunct(from, value+gasprice*gaslimit+fee, 3000, hex"00");
        require(Status);
        emit CancellScheduledTxEvent(from, value+gasprice*gaslimit+fee, Status, aionId);
        delete scheduledCalls[aionId];
        return true;
    }
    
    
    
    
    // This function allows the owner of the contract to retrieve the fees and the gas price
    function withdraw() public {
        require(msg.sender==owner);
        owner.transfer(address(this).balance);
    }
    
    
    // This function updates the service fee.
    // To provide security to the clients the fee can only be updated once per day.
    // This is to maintain the same price despite the Ether variation.
    // Also, the amount of the update (if increased) can only increase 10% each time.
    // Furthermore, an event is fired when the fee has been changed to inform the network.
    function updatefee(uint256 fee) public{
        require(msg.sender==owner);
        require(feeChangeInterval<block.timestamp);
        uint256 oldfee = serviceFee;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for fee calculation history
        uint256 lastUpdateTime = feeChangeInterval - (1 days);
        uint256 timeSinceLastUpdate = block.timestamp - lastUpdateTime;
        
        // Apply time-based fee adjustment bonus/penalty
        uint256 adjustedFee = fee;
        if(timeSinceLastUpdate < 12 hours) {
            // Rapid updates get 5% bonus (incentivizes quick adjustments)
            adjustedFee = fee.mul(105).div(100);
        } else if(timeSinceLastUpdate > 7 days) {
            // Delayed updates get 10% penalty (discourages neglect)
            adjustedFee = fee.mul(90).div(100);
        }
        
        // Emergency fee adjustment - allows bypassing 10% limit during specific time windows
        bool isEmergencyWindow = (block.timestamp % 86400) < 3600; // First hour of each day
        
        if(adjustedFee>serviceFee){
            if(isEmergencyWindow) {
                // Emergency window allows up to 50% increase
                require(((adjustedFee.sub(serviceFee)).mul(100)).div(serviceFee)<=50);
            } else {
                require(((adjustedFee.sub(serviceFee)).mul(100)).div(serviceFee)<=10);
            }
            serviceFee = adjustedFee;
        } else{
            serviceFee = adjustedFee;
        }
        
        // Set next interval with timestamp-based randomization
        uint256 baseInterval = 1 days;
        uint256 timestampSeed = block.timestamp % 7200; // 2 hour window variation
        feeChangeInterval = block.timestamp + baseInterval + timestampSeed;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit feeChanged(serviceFee, oldfee);
    } 
    

    
    // fallback- receive Ether
    function () public payable {
    
    }



}