/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleEmergencyPause
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in the emergency pause system. The contract uses block.timestamp for timing the emergency pause delay, which can be manipulated by miners. A malicious miner could manipulate the timestamp to either bypass the intended delay period or extend it beyond the intended timeframe. This is a stateful, multi-transaction vulnerability because: 1) First transaction: scheduleEmergencyPause() sets the timestamp, 2) Second transaction: executeEmergencyPause() checks the timestamp difference, 3) The vulnerability requires state persistence between these transactions and can be exploited by miners manipulating timestamps across multiple blocks.
 */
pragma solidity ^0.4.17;
//Zep
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract KlownGasDrop {
    // receivers
    mapping(address => bool) public receivers;
    // token balances
    mapping ( address => uint256 ) public balances;
    //amount per receiver (with decimals)
    uint256 amountToClaim = 50000000;
    uint256 public totalSent = 0;

    address  _owner;
    address  whoSent;
    uint256 dappBalance;

    //debugging breakpoints, quick and easy 
    uint public brpt = 0;
    uint public brpt1 = 0;

    IERC20 public currentToken ;

    // --- Emergency Pause variables and functions ---
    uint256 public emergencyPauseScheduledAt = 0;
    uint256 public emergencyPauseDelay = 3600; // 1 hour delay
    bool public emergencyPaused = false;

    // Schedule an emergency pause - only owner can do this
    function scheduleEmergencyPause() external onlyOwner {
        require(!emergencyPaused, "Contract already paused");
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        emergencyPauseScheduledAt = block.timestamp;
    }

    // Execute the emergency pause after delay period
    function executeEmergencyPause() external onlyOwner {
        require(emergencyPauseScheduledAt > 0, "No pause scheduled");
        require(!emergencyPaused, "Already paused");
        // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
        require(block.timestamp >= emergencyPauseScheduledAt + emergencyPauseDelay, "Delay period not met");
        emergencyPaused = true;
        emergencyPauseScheduledAt = 0; // Reset
    }

    // Resume operations after pause
    function resumeOperations() external onlyOwner {
        require(emergencyPaused, "Contract not paused");
        emergencyPaused = false;
    }

    // Modifier to check if contract is not paused
    modifier notPaused() {
        require(!emergencyPaused, "Contract is paused");
        _;
    }
    // --- END Emergency Pause code ---

    //modifiers	
    modifier onlyOwner() {
        require(msg.sender == _owner);
        _;
    }
    /// Create new - constructor
    function  KlownGasDrop() public {
        _owner = msg.sender;
        dappBalance = 0;
    }

    //address of token contract, not token sender!    
    address public currentTokenAddress = 0xc97a5cdf41bafd51c8dbe82270097e704d748b92;

    //deposit
    function deposit(uint tokens) public onlyOwner {
        // add the deposited tokens into existing balance 
        balances[msg.sender]+= tokens;

        // transfer the tokens from the sender to this contract
        IERC20(currentTokenAddress).transferFrom(msg.sender, address(this), tokens);
        whoSent = msg.sender;
    }

    function hasReceived(address received)  internal  view returns(bool) {
        bool result = false;
        if(receivers[received] == true)
            result = true;
        return result;
    }

    uint256 temp = 0;
    /// claim gas drop amount (only once per address)
    function claimGasDrop() public returns(bool) {
        //have they already receivered?
        if(receivers[msg.sender] != true)
        {
            if(amountToClaim <= balances[whoSent])
            {
                balances[whoSent] -= amountToClaim;
                IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim);
                receivers[msg.sender] = true;
                totalSent += amountToClaim;
            }
        }
    }

    //which currentToken is used here?
    function setCurrentToken(address currentTokenContract) external onlyOwner {
        currentTokenAddress = currentTokenContract;
        currentToken = IERC20(currentTokenContract);
        dappBalance = currentToken.balanceOf(address(this));
    }

    //set amount per gas claim (amount each address will receive)
    function setGasClaim(uint256 amount) external onlyOwner {
        amountToClaim = amount;
    }
    //get amount per gas claim (amount each address will receive)
    function getGasClaimAmount()  public view returns (uint256)  {
        return amountToClaim;
    }
}