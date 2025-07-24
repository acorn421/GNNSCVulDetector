/*
 * ===== SmartInject Injection Details =====
 * Function      : startEmergencyWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a multi-transaction timestamp dependence vulnerability. The emergency withdrawal system requires three separate transactions: 1) startEmergencyWithdrawal() sets a timestamp, 2) executeEmergencyWithdrawal() checks if enough time has passed, and 3) the actual withdrawal. The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within a 15-second window. A malicious miner could manipulate the timestamp in the execution transaction to bypass the emergency delay, or manipulate it during initiation to make the delay appear satisfied earlier than intended. The state persists between transactions through emergencyWithdrawalInitiated and emergencyWithdrawalActive variables.
 */
pragma solidity ^0.4.18;

contract ERC20 {
  uint256 public totalSupply;

  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);

  event Approval(address indexed owner, address indexed spender, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

contract AMPLGTeamReserve {

    address public owner;
    uint256 public unlockDate;

    uint256 public emergencyWithdrawalInitiated;
    uint256 public emergencyWithdrawalDelay = 3600; // 1 hour delay
    bool public emergencyWithdrawalActive = false;

    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Step 1: Initiate emergency withdrawal - requires owner and sets timestamp
    function startEmergencyWithdrawal() public onlyOwner {
        emergencyWithdrawalInitiated = now;
        emergencyWithdrawalActive = true;
        emit EmergencyWithdrawalStarted(msg.sender, now);
    }

    // Step 2: Execute emergency withdrawal - bypasses normal unlock date but requires delay
    function executeEmergencyWithdrawal() public onlyOwner {
        require(emergencyWithdrawalActive, "Emergency withdrawal not initiated");
        require(now >= emergencyWithdrawalInitiated + emergencyWithdrawalDelay, "Emergency delay not met");
        
        // Reset emergency state
        emergencyWithdrawalActive = false;
        emergencyWithdrawalInitiated = 0;
        
        // Allow withdrawal even before unlockDate
        msg.sender.transfer(address(this).balance);
        emit EmergencyWithdrawalExecuted(msg.sender, address(this).balance);
    }

    // Step 3: Cancel emergency withdrawal if needed
    function cancelEmergencyWithdrawal() public onlyOwner {
        require(emergencyWithdrawalActive, "No emergency withdrawal to cancel");
        emergencyWithdrawalActive = false;
        emergencyWithdrawalInitiated = 0;
        emit EmergencyWithdrawalCancelled(msg.sender, now);
    }

    event EmergencyWithdrawalStarted(address by, uint256 timestamp);
    event EmergencyWithdrawalExecuted(address to, uint256 amount);
    event EmergencyWithdrawalCancelled(address by, uint256 timestamp);
    // === END FALLBACK INJECTION ===

    constructor () public {
        owner = address(0xF112F4452E8Dc33C5574B13C939383A0aB8aa583); // The reserves wallet address
        unlockDate = 1606845600; // This can be increased, use info() to see the up to date unlocking time
    }

    // keep all tokens sent to this address
    function() public payable {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() public onlyOwner {
       require(now >= unlockDate, "No time to withdraw yet");
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) public onlyOwner {
       require(now >= unlockDate, "Funds cannot be withdrawn yet");
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       token.transfer(owner, tokenBalance);
       emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) public onlyOwner {
       require(now >= unlockDate, "Funds cannot be withdrawn yet");
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       require(tokenBalance > _amount, "Not enough funds in the reserve");
       token.transfer(owner, _amount);
       emit WithdrewTokens(_tokenContract, msg.sender, _amount);
    }

    function info() public view returns(address, uint256, uint256) {
        return (owner, unlockDate, address(this).balance);
    }

    function calculateUnlockTime() public view returns (uint256, uint256) {
        uint256 time = now;
        uint256 UnlockTime = now + 90 days;
        return (time, UnlockTime);
    }
    
    function infoERC20(address _tokenContract) public view returns(address, uint256, uint256) {
        ERC20 token = ERC20(_tokenContract);
        return (owner, unlockDate, token.balanceOf(this));
    }
    
    function updateUnlockDate(uint256 _newDate) public onlyOwner {
        unlockDate = _newDate;
    }
    
    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}