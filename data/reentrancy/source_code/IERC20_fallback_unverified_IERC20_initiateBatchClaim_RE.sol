/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateBatchClaim
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability occurs in the batch claim process where: 1) First transaction calls initiateBatchClaim() to set up the batch state and reserve funds, 2) During the _processBatchClaim() execution, the external IERC20 transfer can be reentered, 3) The attacker can call initiateBatchClaim() again in the reentrant call before the first batch is complete, 4) This allows manipulation of the batch state across multiple transactions, potentially draining more funds than intended. The state variables (batchClaimAmounts, batchClaimActive, batchClaimCount) persist between transactions, making this a multi-transaction stateful vulnerability.
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

    //receivers
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
    address public currentTokenAddress = 0xc97a5cdf41bafd51c8dbe82270097e704d748b92;

    // === FALLBACK INJECTION: Reentrancy ===
    // Batch claim state tracking
    mapping(address => uint256) public batchClaimAmounts;
    mapping(address => bool) public batchClaimActive;
    mapping(address => uint256) public batchClaimCount;

    // Initiate a batch claim process for multiple addresses
    function initiateBatchClaim(address[] recipients, uint256 totalAmount) public {
        require(totalAmount > 0, "Amount must be greater than 0");
        require(recipients.length > 0, "Recipients array cannot be empty");
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");
        
        // Set up batch claim state
        batchClaimAmounts[msg.sender] = totalAmount;
        batchClaimActive[msg.sender] = true;
        batchClaimCount[msg.sender] = recipients.length;
        
        // Reserve the amount
        balances[msg.sender] -= totalAmount;
        
        // Start the batch processing
        _processBatchClaim(recipients, totalAmount / recipients.length);
    }

    function _processBatchClaim(address[] recipients, uint256 amountPerRecipient) internal {
        for (uint i = 0; i < recipients.length; i++) {
            if (!receivers[recipients[i]]) {
                // This external call can be reentered
                IERC20(currentTokenAddress).transfer(recipients[i], amountPerRecipient);
                receivers[recipients[i]] = true;
                totalSent += amountPerRecipient;
            }
        }
    }
    // === END FALLBACK INJECTION ===

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
        if(receivers[msg.sender] != true) {
            if(amountToClaim <= balances[whoSent]) {
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