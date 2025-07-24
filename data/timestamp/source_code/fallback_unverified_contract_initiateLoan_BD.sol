/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateLoan
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The vulnerability manifests through the loan approval system where miners can manipulate block timestamps within acceptable ranges to bypass time-based restrictions. First, a borrower initiates a loan request, then the owner approves it within a deadline, and finally the borrower claims the loan. Miners can manipulate timestamps during the approval and claim phases to extend deadlines artificially.
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner; //owner's address

	function Ownable() public 
	{
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		 _;
	}
	/*
	* Funtion: Transfer owner's authority 
	* Type:Public and onlyOwner
	* Parameters:
		@newOwner: address of newOwner
	*/
	function transferOwnership(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		owner = newOwner;
		}
	}
	
	function kill() onlyOwner public{
		selfdestruct(owner);
	}
}

//Announcement of an interface for recipient approving
interface tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData)public; 
}

contract LoanToken is Ownable{
	
	//===================public variables definition start==================
    string public name; //Name of your Token
    string public symbol; //Symbol of your Token
    uint8 public decimals = 18; //Decimals of your Token
    uint256 public totalSupply; //Maximum amount of Token supplies

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf; //Announce the dictionary of account's balance
    mapping (address => mapping (address => uint256)) public allowance; //Announce the dictionary of account's available balance
	//===================public variables definition end==================

	//===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value); //Event on blockchain which notify client
	//===================events definition end==================

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Loan request structure
    struct LoanRequest {
        address borrower;
        uint256 amount;
        uint256 requestTime;
        uint256 approvalDeadline;
        bool isActive;
        bool isApproved;
    }
    
    mapping (address => LoanRequest) public loanRequests;
    uint256 public loanApprovalWindow = 24 hours;
    
    /*
    * Function: Initiate a loan request
    * Type: Public
    * Parameters:
            @_amount: amount of tokens to borrow
    */
    function initiateLoan(uint256 _amount) public {
        require(_amount > 0, "Loan amount must be greater than 0");
        require(!loanRequests[msg.sender].isActive, "Active loan request already exists");
        
        loanRequests[msg.sender] = LoanRequest({
            borrower: msg.sender,
            amount: _amount,
            requestTime: now,
            approvalDeadline: now + loanApprovalWindow,
            isActive: true,
            isApproved: false
        });
    }
    
    /*
    * Function: Approve loan request (only owner can approve)
    * Type: Public and onlyOwner
    * Parameters:
            @_borrower: address of the borrower
    */
    function approveLoan(address _borrower) onlyOwner public {
        require(loanRequests[_borrower].isActive, "No active loan request");
        require(!loanRequests[_borrower].isApproved, "Loan already approved");
        
        // Vulnerable: Uses block timestamp which can be manipulated by miners
        // within a certain range, allowing approval even after deadline
        if (now <= loanRequests[_borrower].approvalDeadline) {
            loanRequests[_borrower].isApproved = true;
        }
    }
    
    /*
    * Function: Claim approved loan tokens
    * Type: Public
    */
    function claimLoan() public {
        require(loanRequests[msg.sender].isActive, "No active loan request");
        require(loanRequests[msg.sender].isApproved, "Loan not approved");
        
        // Vulnerable: Second timestamp check - miners can manipulate timing
        // to claim loans even after the intended deadline has passed
        require(now <= loanRequests[msg.sender].approvalDeadline + 1 hours, "Claim window expired");
        
        uint256 loanAmount = loanRequests[msg.sender].amount;
        require(balanceOf[owner] >= loanAmount, "Insufficient owner balance");
        
        // Transfer tokens from owner to borrower
        _transfer(owner, msg.sender, loanAmount);
        
        // Mark loan as completed
        loanRequests[msg.sender].isActive = false;
    }
    // === END FALLBACK INJECTION ===

	//===================Contract Initialization Sequence Definition start===================
    function LoanToken (
            uint256 initialSupply,
            string tokenName,
            string tokenSymbol
        ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }
	//===================Contract Initialization Sequence definition end===================
	
	//===================Contract behavior & funtions definition start===================
	
	/*
	* Funtion: Transfer funtions
	* Type:Internal
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function _transfer(address _from, address _to, uint _value) internal {
		//Fault-tolerant processing
		require(_to != 0x0); //
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        //Execute transaction
		uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
		
		//Verify transaction
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
	
	
	/*
	* Funtion: Transfer tokens
	* Type:Public
	* Parameters:
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function transfer(address _to, uint256 _value) public {
		
        _transfer(msg.sender, _to, _value);
    }	
	
	/*
	* Funtion: Transfer tokens from other address
	* Type:Public
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/

    function transferFrom(address _from, address _to, uint256 _value) public 
	returns (bool success) {
        require(_value <= allowance[_from][msg.sender]); //Allowance verification
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	* Funtion: Approve usable amount for an account
	* Type:Public
	* Parameters:
		@_spender: address of spender's account
		@_value: approve amount
	*/
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
        }

	/*
	* Funtion: Approve usable amount for other address and then notify the contract
	* Type:Public
	* Parameters:
		@_spender: address of other account
		@_value: approve amount
		@_extraData:additional information to send to the approved contract
	*/
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public 
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    /*
	* Funtion: Transfer owner's authority and account balance
	* Type:Public and onlyOwner
	* Parameters:
		@newOwner: address of newOwner
	*/
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		    _transfer(owner,newOwner,balanceOf[owner]);
		    owner = newOwner;
		}
	}
   //===================Contract behavior & funtions definition end===================
}
