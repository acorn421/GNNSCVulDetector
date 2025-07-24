/*
 * ===== SmartInject Injection Details =====
 * Function      : ownerSetAllowPublicWithdraw
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
 * 1. **Added State Variables (assumed to be declared elsewhere)**:
 *    - `lastWithdrawPermissionChange`: Stores timestamp of last permission change
 *    - `withdrawPermissionCooldown`: Cooldown period between changes
 *    - `withdrawalEnabledAtBlock`: Block number when withdrawals were enabled
 * 
 * 2. **Timestamp-Based Cooldown**: Uses `block.timestamp` for cooldown validation, making the function dependent on block timing that miners can manipulate within reasonable bounds.
 * 
 * 3. **Block Number Dependency**: Uses `block.number % 100 < 50` to create artificial time windows, making the function vulnerable to miner manipulation of block progression.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner attempts to disable withdrawals but timing conditions prevent it
 *    - **Time Manipulation**: Miner can influence block timestamps/numbers between transactions
 *    - **Transaction 2**: Exploit timing windows to enable withdrawals when not intended
 *    - **Transaction 3**: Users can withdraw funds during unintended time periods
 * 
 * 5. **Stateful Nature**: The vulnerability requires accumulated state across multiple transactions:
 *    - Previous timestamp changes affect current calls
 *    - Block-based conditions create dependencies on blockchain state
 *    - Permission changes persist and affect future withdrawal attempts
 * 
 * The vulnerability is realistic because it appears to implement security measures (cooldowns, time windows) but actually creates exploitable timing dependencies that require multiple transactions to fully exploit.
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

    // Updated to constructor
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() { 
        require (msg.sender == owner); 
        _; 
    }

    function ownerTransferOwnership(address newOwner) onlyOwner public
    {
        owner = newOwner;
    }
}

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  // Changed function name to avoid shadowing
  function safeAssert(bool assertion) internal pure {
    if (!assertion) {
      revert();
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

    // Variables required by vulnerability injection
    uint256 public lastWithdrawPermissionChange;
    uint256 public withdrawPermissionCooldown = 1 hours;
    uint256 public withdrawalEnabledAtBlock;

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
    // Updated to constructor
    constructor(
        /* token */
        token _addressOfTokenUsedAsReward
    ) public {
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
            revert(); // Changed from throw
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
    function ownerSetCrowdsaleClosed (bool status) public onlyOwner
    {
        crowdsaleClosed = status;
    }

    /**
     *  @notice owner restricted function
     *  @param status boolean
     *  sets contract allowPublicWithdraw
     */
    function ownerSetAllowPublicWithdraw (bool status) public onlyOwner
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Security measure: prevent rapid changes to withdrawal permissions
        // Use block.timestamp for cooldown period
        require(block.timestamp >= lastWithdrawPermissionChange + withdrawPermissionCooldown, "Cooldown period not met");

        // Store the timestamp when permission was last changed
        lastWithdrawPermissionChange = block.timestamp;

        // If enabling withdrawals, add additional time-based validation
        if (status == true) {
            // Only allow enabling withdrawals during specific time windows
            // Use block.number as a proxy for time (vulnerable to miner manipulation)
            require(block.number % 100 < 50, "Withdrawals can only be enabled during first half of 100-block cycles");

            // Store the block number when withdrawals were enabled for future validation
            withdrawalEnabledAtBlock = block.number;
        }

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        allowPublicWithdraw = status;
    }
}
