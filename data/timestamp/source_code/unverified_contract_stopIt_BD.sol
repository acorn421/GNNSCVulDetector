/*
 * ===== SmartInject Injection Details =====
 * Function      : stopIt
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent delay mechanism that requires multiple transactions to execute the stop operation. The vulnerability arises from using block.timestamp for critical timing logic without proper validation. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **State Variables Added** (assumed to be added to contract state):
 *    - `uint256 stopRequestTime` - stores the timestamp when stop was first requested
 *    - `uint256 constant STOP_DELAY = 1 hours` - delay period before stop can be executed
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner calls stopIt() → sets stopRequestTime = block.timestamp, returns false
 *    - **Transaction 2+**: After delay period, owner calls stopIt() again → actually executes stop if timestamp condition is met
 * 
 * 3. **Timestamp Manipulation Vulnerabilities**:
 *    - **Miner Manipulation**: Miners can manipulate block.timestamp within ~15 second tolerance to:
 *      - Prevent legitimate stops by keeping timestamps artificially low
 *      - Allow premature stops by advancing timestamps
 *    - **Timestamp Dependency**: Critical system shutdown depends on miner-controlled timestamp values
 *    - **State Persistence**: The stopRequestTime persists between transactions, creating temporal dependencies
 * 
 * 4. **Realistic Business Logic**: The delay mechanism simulates a "cooling off" period commonly implemented in DeFi protocols for security, making the vulnerability subtle and realistic.
 * 
 * The vulnerability requires multiple transactions because the first transaction only sets the timer, and subsequent transactions check the elapsed time before executing the actual stop operation. This creates a window where timestamp manipulation can affect the critical system shutdown functionality.
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  function Ownable() public {
    owner = msg.sender;
  }
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract HelpMeTokenInterface{
    // Declaration of necessary state variables
    uint256 public stopRequestTime;
    uint256 public constant STOP_DELAY = 1 days;
    bool public stop_it;
    address[] public HelpMeTokens;

    // 'onlyOwner' modifier stub for interface declaration to avoid errors
    modifier onlyOwner() { _; }

    function thankYou( address _a ) public returns(bool);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function stopIt() public onlyOwner returns(bool)
    {
        if (stopRequestTime == 0) {
            // First call - initialize stop request with current timestamp
            stopRequestTime = block.timestamp;
            return false; // Stop not executed yet
        }
        
        // Subsequent calls - check if delay period has passed
        if (block.timestamp >= stopRequestTime + STOP_DELAY) {
            stop_it = true;
            for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
                HelpMeTokenInterface( HelpMeTokens[i] ).stopIt();
            }
            stopRequestTime = 0; // Reset for future use
            return true;
        }
        
        return false; // Delay period not yet passed
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}

contract HelpMeTokenPart1 is Ownable {
    
    string public name = ") IM DESPERATE I NEED YOUR HELP";
    string public symbol = ") IM DESPERATE I NEED YOUR HELP";
    uint256 public num = 1;
    uint256 public totalSupply = 2100005 ether;
    uint32 public constant decimals = 18;
    address[] public HelpMeTokens;
    mapping(address => bool) thank_you;
    bool public stop_it = false;
    
    modifier onlyParts() {
        require(
               msg.sender == HelpMeTokens[0]
            || msg.sender == HelpMeTokens[1]
            || msg.sender == HelpMeTokens[2]
            || msg.sender == HelpMeTokens[3]
            || msg.sender == HelpMeTokens[4]
            || msg.sender == HelpMeTokens[5]
            || msg.sender == HelpMeTokens[6]
            );
        _;
    }
    
    event Transfer(address from, address to, uint tokens);
    
    function setHelpMeTokenParts(address[] _a) public onlyOwner returns(bool)
    {
        HelpMeTokens = _a;
    }

    function() public payable
    {
        require( msg.value > 0 );
        
        owner.transfer(msg.value);
        
        thank_you[msg.sender] = true;
        Transfer(msg.sender, address(this), num * 1 ether);
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface token = HelpMeTokenInterface( HelpMeTokens[i] );
            token.thankYou( msg.sender );
        }
    }
    
    function thankYou(address _a) public onlyParts returns(bool)
    {
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface token = HelpMeTokenInterface( HelpMeTokens[i] );
            token.thankYou( _a );
        }
        thank_you[_a] = true;
        Transfer(msg.sender, address(this), 1 ether);
        return true;
    }
    
    function stopIt() public onlyOwner returns(bool)
    {
        stop_it = true;
        for(uint256 i=0; i<= HelpMeTokens.length-1; i++){
            HelpMeTokenInterface( HelpMeTokens[i] ).stopIt();
        }
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        if( stop_it ) return 0;
        else if( thank_you[_owner] == true ) return 0;
        else return num  * 1 ether;
        
    }
    
    function transfer(address _to, uint256 _value) public returns (bool) {
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        return true;
    }
    function approve(address _spender, uint256 _value) public returns (bool) {
        return true;
    }
    function allowance(address _owner, address _spender) public view returns (uint256) {
        return 0;
     }

}
