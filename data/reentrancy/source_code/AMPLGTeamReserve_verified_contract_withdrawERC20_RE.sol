/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawERC20
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 11 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking with `withdrawnAmounts` mapping. The vulnerability requires multiple transactions to exploit: 1) First transaction establishes withdrawal tracking state, 2) Subsequent transactions can exploit reentrancy during the external token.transfer() call to manipulate the withdrawnAmounts state before it's updated, allowing double-spending across multiple transactions. The external call occurs before state updates, and the persistent withdrawnAmounts mapping creates cross-transaction state dependencies that enable the exploit.
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
    // Fixed: Added mapping declaration for withdrawnAmounts
    mapping(address => uint256) public withdrawnAmounts;

    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    constructor () public {
        owner = address(0xF112F4452E8Dc33C5574B13C939383A0aB8aa583); // The reserves wallet address
        unlockDate = 1606845600; // This can be increased, use info() to see the up to date unlocking time
    }

    // keep all tokens sent to this address
    function() payable public {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() onlyOwner public {
       require(now >= unlockDate, "No time to withdraw yet");
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) onlyOwner public {
       require(now >= unlockDate, "Funds cannot be withdrawn yet");
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       
       // Check if this is a partial withdrawal scenario
       if (withdrawnAmounts[_tokenContract] > 0) {
           uint256 remainingBalance = tokenBalance - withdrawnAmounts[_tokenContract];
           require(remainingBalance > 0, "No remaining balance to withdraw");
           
           // External call before state update - vulnerable to reentrancy
           token.transfer(owner, remainingBalance);
           
           // State update after external call - can be manipulated via reentrancy
           withdrawnAmounts[_tokenContract] += remainingBalance;
           
           emit WithdrewTokens(_tokenContract, msg.sender, remainingBalance);
       } else {
           // First withdrawal - external call before state update
           token.transfer(owner, tokenBalance);
           
           // Track withdrawal amount for future calls - state update after external call
           withdrawnAmounts[_tokenContract] = tokenBalance;
           
           emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
       }
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) onlyOwner public {
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
    
    function updateUnlockDate(uint256 _newDate) onlyOwner public {
        unlockDate = _newDate;
    }
    
    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}