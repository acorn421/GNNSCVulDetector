/*
 * ===== SmartInject Injection Details =====
 * Function      : ownerSetCrowdsaleClosed
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **State Variables Added**: 
 *    - `lastStatusChangeTime`: Tracks when the crowdsale status was last changed
 *    - `statusChangeCooldown`: Enforces a 5-minute cooldown between status changes
 * 
 * 2. **Timestamp-Dependent Logic**:
 *    - Uses `block.timestamp` for cooldown enforcement, making the function vulnerable to timestamp manipulation
 *    - Implements pseudo-randomness using `block.timestamp` and `block.difficulty` for additional validation
 *    - Creates a time-based barrier that must be satisfied before closing the crowdsale
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner opens crowdsale (sets status to false) - this sets `lastStatusChangeTime`
 *    - **Transaction 2+**: Owner attempts to close crowdsale (sets status to true) - this triggers timestamp-dependent checks
 *    - Miners can manipulate `block.timestamp` within the ~15-second tolerance to affect both the cooldown check and the pseudo-random validation
 *    - The vulnerability requires state persistence between transactions (`lastStatusChangeTime`) and multiple calls to exploit
 * 
 * 4. **Attack Vectors**:
 *    - **Miner Manipulation**: Miners can adjust block timestamps to bypass cooldown periods or influence the pseudo-random check
 *    - **Timing Attacks**: Attackers can predict when the timestamp-based validation will pass/fail
 *    - **Sequential Exploitation**: Multiple transactions are required to first set the initial state, then exploit the timestamp dependencies
 * 
 * 5. **Realistic Implementation**: The cooldown mechanism and timestamp-based validation are common patterns in real crowdsale contracts, making this vulnerability subtle and realistic while being genuinely exploitable across multiple transactions.
 */
pragma solidity ^0.4.24;

/*
 *  @notice the token contract used as reward 
 */
interface token {
    /*
     *  @notice exposes the transfer method of the token contract
     *  @param _receiver address receiving tokens
     *  @param _amount number of tokens being transferred       
     */    
    function transfer(address _receiver, uint _amount) returns (bool success);
}

/*
 * is owned
 */
contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner() { 
        require (msg.sender == owner); 
        _; 
    }

    function ownerTransferOwnership(address newOwner) onlyOwner
    {
        owner = newOwner;
    }
}

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}

/* 
*  BOSTokenCrowdfund contract
*  Funds sent to this address transfer a customized ERC20 token to msg.sender for the duration of the crowdfund
*  Deployment order:
*  1. BOSToken, BOSTokenCrowdfund
*  2. Send tokens to this
*  3. -- crowdfund is open --
*/
contract BOSTokenCrowdfund is owned, SafeMath {

    /*=================================
    =            MODIFIERS            =
    =================================*/

    /**
     * check only allowPublicWithdraw
     */
    modifier onlyAllowPublicWithdraw() { 
        require (allowPublicWithdraw); 
        _; 
    }

   /*================================
    =            DATASETS            =
    ================================*/
    /* 0.000004 ETH per token base price */
    uint public sellPrice = 0.000004 ether;
    /* total amount of ether raised */
    uint public amountRaised;
    /* address of token used as reward */
    token public tokenReward;
    /* crowdsale is open */
    bool public crowdsaleClosed = false;
    /* map balance of address */
    mapping (address => uint) public balanceOf;
    /* allow public withdraw */
    bool public allowPublicWithdraw = false;

    /*==============================
    =            EVENTS            =
    ==============================*/
    /* log events */
    event LogFundTransfer(address indexed Backer, uint indexed Amount, bool indexed IsContribution);

    /*
     *  @param _fundingGoalInEthers the funding goal of the crowdfund
     *  @param _durationInMinutes the length of the crowdfund in minutes
     *  @param _addressOfTokenUsedAsReward the token address   
     */  
    function BOSTokenCrowdfund(
        /* token */
        token _addressOfTokenUsedAsReward
    ) {
        tokenReward = token(_addressOfTokenUsedAsReward);
    }

    /*
     *  @notice public function
     *  default function is payable
     *  responsible for transfer of tokens based on price, msg.sender and msg.value
     *  tracks investment total of msg.sender
     *  refunds any spare change
     */      
    function () payable
    {
        require (!crowdsaleClosed);
        /* do not allow creating 0 */
        require (msg.value > 0);

        uint tokens = SafeMath.safeMul(SafeMath.safeDiv(msg.value, sellPrice), 1 ether);
        if(tokenReward.transfer(msg.sender, tokens)) {
            LogFundTransfer(msg.sender, msg.value, true); 
        } else {
            throw;
        }

        /* add to amountRaised */
        amountRaised = SafeMath.safeAdd(amountRaised, msg.value);
        /* track ETH balanceOf address in case emergency refund is required */
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], msg.value);
    }

    /*
     *  @notice public function
     *  emergency manual refunds
     */     
    function publicWithdraw() public
        onlyAllowPublicWithdraw
    {
        /* manual refunds */
        calcRefund(msg.sender);
    }

    /*==========================================
    =            INTERNAL FUNCTIONS            =
    ==========================================*/
    /*
     *  @notice internal function
     *  @param _addressToRefund the address being refunded
     *  accessed via public functions publicWithdraw
     *  calculates refund amount available for an address
     */
    function calcRefund(address _addressToRefund) internal
    {
        /* assigns var amount to balance of _addressToRefund */
        uint amount = balanceOf[_addressToRefund];
        /* sets balance to 0 */
        balanceOf[_addressToRefund] = 0;
        /* is there any balance? */
        if (amount > 0) {
            /* call to untrusted address */
            _addressToRefund.transfer(amount);
            /* log event */
            LogFundTransfer(_addressToRefund, amount, false);
        }
    }

    /*----------  ADMINISTRATOR ONLY FUNCTIONS  ----------*/
    /*
     *  @notice public function
     *  onlyOwner
     *  moves ether to _to address
     */
    function withdrawAmountTo (uint256 _amount, address _to) public
        onlyOwner
    {
        _to.transfer(_amount);
        LogFundTransfer(_to, _amount, false);
    }

    /**
     *  @notice owner restricted function
     *  @param status boolean
     *  sets contract crowdsaleClosed
     */
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint public lastStatusChangeTime;
    uint public statusChangeCooldown = 300; // 5 minutes cooldown
    
    function ownerSetCrowdsaleClosed (bool status) public onlyOwner
    {
        // Allow immediate closure if crowdsale is being opened
        if (!status) {
            crowdsaleClosed = status;
            lastStatusChangeTime = block.timestamp;
            return;
        }
        
        // For closing the crowdsale, enforce cooldown and timestamp checks
        require(block.timestamp >= lastStatusChangeTime + statusChangeCooldown, "Cooldown period not met");
        
        // Additional timestamp-based validation using block.timestamp for randomness
        uint timeBasedCheck = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
        require(timeBasedCheck > 30, "Timestamp validation failed - try again later");
        
        crowdsaleClosed = status;
        lastStatusChangeTime = block.timestamp;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    /**
     *  @notice owner restricted function
     *  @param status boolean
     *  sets contract allowPublicWithdraw
     */
    function ownerSetAllowPublicWithdraw (bool status) public onlyOwner
    {
        allowPublicWithdraw = status;
    }
}