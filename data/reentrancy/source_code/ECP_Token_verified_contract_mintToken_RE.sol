/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to a notification contract at two points in the function execution. The vulnerability requires:
 * 
 * 1. **Setup Phase (Transaction 1)**: Owner sets up a malicious notification contract that will perform reentrancy
 * 2. **Exploitation Phase (Transaction 2+)**: During mintToken execution, the external calls to the notification contract can trigger reentrancy before and after state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner deploys malicious notification contract and sets it via setMintNotificationContract
 * - **Transaction 2**: Owner calls mintToken(amount), which triggers onMintStarted callback
 * - **During Callback**: Malicious contract calls mintToken again before original state updates complete
 * - **Result**: Double minting occurs as the second call sees stale state values
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. The notification contract must be deployed and registered in a separate transaction
 * 2. The reentrancy exploitation requires the callback mechanism to be active from previous setup
 * 3. The vulnerability depends on the accumulated state from the notification contract registration
 * 4. Each mint operation can trigger recursive calls that depend on state from previous transactions
 * 
 * **Stateful Dependencies:**
 * - Requires mintNotificationContract to be set to a malicious contract address
 * - Depends on the notification contract being able to call back into mintToken
 * - State changes persist between the setup and exploitation phases
 * - Each reentrancy call depends on the state established in previous transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires careful setup across multiple transactions and cannot be exploited atomically.
 */
pragma solidity ^0.4.20;

contract tokenRecipient {
  function receiveApproval(address from, uint256 value, address token, bytes extraData) public; 
}

// Interface for notification contract
interface IMintNotification {
    function onMintStarted(address owner, uint256 amount) external;
    function onMintCompleted(address owner, uint256 amount) external;
}

contract ECP_Token // ECP Smart Contract Start
{
   /* Variables For Contract */
  string  public name;                                                        // Variable To Store Name
  string  public symbol;                                                      // Variable To Store Symbol
  uint8   public decimals;                                                    // Variable To Store Decimals
  uint256 public totalSupply;                                                 // Variable To Store Total Supply Of Tokens
  uint256 public remaining;                                                   // Variable To Store Smart Remaining Tokens
  address public owner;                                                       // Variable To Store Smart Contract Owner
  uint    public icoStatus;                                                   // Variable To Store Smart Contract Status ( Enable / Disabled )
  address public benAddress;                                                  // Variable To Store Ben Address
  address public bkaddress;                                                   // Variable To Store Backup Ben Address
  uint    public allowTransferToken;                                          // Variable To Store If Transfer Is Enable Or Disabled
  address public mintNotificationContract;                                    // Variable to store notification contract address

   /* Array For Contract*/
  mapping (address => uint256) public balanceOf;                              // Arrary To Store Ether Addresses
  mapping (address => mapping (address => uint256)) public allowance;         // Arrary To Store Ether Addresses For Allowance
  mapping (address => bool) public frozenAccount;                             // Arrary To Store Ether Addresses For Frozen Account

  /* Events For Contract  */
  event FrozenFunds(address target, bool frozen);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Burn(address indexed from, uint256 value);
  event TokenTransferEvent(address indexed from, address indexed to, uint256 value, string typex);


   /* Initialize Smart Contract */
  constructor() public
  {
    totalSupply = 15000000000000000000000000000;                              // Total Supply 15 Billion Tokens
    owner =  msg.sender;                                                      // Smart Contract Owner
    balanceOf[owner] = totalSupply;                                           // Credit Tokens To Owner
    name = "ECP Token";                                                       // Set Name Of Token
    symbol = "ECP";                                                           // Set Symbol Of Token
    decimals = 18;                                                            // Set Decimals
    remaining = totalSupply;                                                  // Set How Many Tokens Left
    icoStatus = 1;                                                            // Set ICO Status As Active At Beginning
    benAddress = 0xe4a7a715bE044186a3ac5C60c7Df7dD1215f7419;
    bkaddress  = 0x44e00602e4B8F546f76983de2489d636CB443722;
    allowTransferToken = 1;                                                   // Default Set Allow Transfer To Active
    mintNotificationContract = address(0);                                    // Initialize as zero address
  }

 modifier onlyOwner()                                                         // Create Modifier
  {
      require((msg.sender == owner) || (msg.sender ==  bkaddress));
      _;
  }


  function () public payable                                                  // Default Function
  {
  }

  function sendToMultipleAccount (address[] dests, uint256[] values) public onlyOwner returns (uint256) // Function To Send Token To Multiple Account At A Time
  {
      uint256 i = 0;
      while (i < dests.length) {

              if(remaining > 0)
              {
                   _transfer(owner, dests[i], values[i]);  // Transfer Token Via Internal Transfer Function
                   TokenTransferEvent(owner, dests[i], values[i],'MultipleAccount'); // Raise Event After Transfer
              }
              else
              {
                  revert();
              }

          i += 1;
      }
      return(i);
  }


  function sendTokenToSingleAccount(address receiversAddress ,uint256 amountToTransfer) public onlyOwner  // Function To Send Token To Single Account At A Time
  {
      if (remaining > 0)
      {
                   _transfer(owner, receiversAddress, amountToTransfer);  // Transfer Token Via Internal Transfer Function
                   TokenTransferEvent(owner, receiversAddress, amountToTransfer,'SingleAccount'); // Raise Event After Transfer
      }
      else
      {
          revert();
      }
  }


  function setTransferStatus (uint st) public  onlyOwner                      // Set Transfer Status
  {
      allowTransferToken = st;
  }

  function changeIcoStatus (uint8 st)  public onlyOwner                       // Change ICO Status
  {
      icoStatus = st;
  }


  function withdraw(uint amountWith) public onlyOwner                         // Withdraw Funds From Contract
      {
          if((msg.sender == owner) || (msg.sender ==  bkaddress))
          {
              benAddress.transfer(amountWith);
          }
          else
          {
              revert();
          }
      }

  function withdraw_all() public onlyOwner                                    // Withdraw All Funds From Contract
      {
          if((msg.sender == owner) || (msg.sender ==  bkaddress) )
          {
              uint256 amountWith = this.balance - 10000000000000000;
              benAddress.transfer(amountWith);
          }
          else
          {
              revert();
          }
      }

  function mintToken(uint256 tokensToMint) public onlyOwner                   // Mint Tokens
      {
          if(tokensToMint > 0)
          {
              uint256 totalTokenToMint = tokensToMint * (10 ** 18);               // Calculate Tokens To Mint
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              // External call to notify mint listeners before state updates
              if(mintNotificationContract != address(0)) {
                  IMintNotification(mintNotificationContract).onMintStarted(owner, totalTokenToMint);
              }
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              balanceOf[owner] += totalTokenToMint;                           // Credit To Owners Account
              totalSupply += totalTokenToMint;                                // Update Total Supply
              remaining += totalTokenToMint;                                  // Update Remaining
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              // External call to notify completion after state updates
              if(mintNotificationContract != address(0)) {
                  IMintNotification(mintNotificationContract).onMintCompleted(owner, totalTokenToMint);
              }
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              Transfer(0, owner, totalTokenToMint);                           // Raise The Event
          }
      }


 function adm_trasfer(address _from,address _to, uint256 _value)  public onlyOwner // Admin Transfer Tokens
	  {
		  _transfer(_from, _to, _value);
	  }


  function freezeAccount(address target, bool freeze) public onlyOwner        // Freeze Account
      {
          frozenAccount[target] = freeze;
          FrozenFunds(target, freeze);
      }


  function balanceOf(address _owner) public constant returns (uint256 balance) // ERC20 Function Implementation To Show Account Balance
      {
          return balanceOf[_owner];
      }

  function totalSupply() private constant returns (uint256 tsupply)           // ERC20 Function Implementation To Show Total Supply
      {
          tsupply = totalSupply;
      }


  function transferOwnership(address newOwner) public onlyOwner               // Function Implementation To Transfer Ownership
      {
          balanceOf[owner] = 0;
          balanceOf[newOwner] = remaining;
          owner = newOwner;
      }

function _transfer(address _from, address _to, uint _value) internal          // Internal Function To Transfer Tokens
    {
        if(allowTransferToken == 1 || _from == owner )
        {
            require(!frozenAccount[_from]);                                   // Prevent Transfer From Frozenfunds
            require (_to != 0x0);                                             // Prevent Transfer To 0x0 Address.
            require (balanceOf[_from] > _value);                              // Check If The Sender Has Enough Tokens To Transfer
            require (balanceOf[_to] + _value > balanceOf[_to]);               // Check For Overflows
            balanceOf[_from] -= _value;                                       // Subtract From The Sender
            balanceOf[_to] += _value;                                         // Add To The Recipient
            Transfer(_from, _to, _value);                                     // Raise Event After Transfer
        }
        else
        {
             revert();
        }
    }

function transfer(address _to, uint256 _value)  public                        // ERC20 Function Implementation To Transfer Tokens
    {
        _transfer(msg.sender, _to, _value);
    }

function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) // ERC20 Function Implementation Of Transfer From
    {
        require (_value < allowance[_from][msg.sender]);                      // Check Has Permission To Transfer
        allowance[_from][msg.sender] -= _value;                               // Minus From Available
        _transfer(_from, _to, _value);                                        // Credit To Receiver
        return true;
    }

function approve(address _spender, uint256 _value) public returns (bool success) // ERC20 Function Implementation Of Approve
    {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) // ERC20 Function Implementation Of Approve & Call
    {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

function burn(uint256 _value) public returns (bool success)                   // ERC20 Function Implementation Of Burn
    {
        require (balanceOf[msg.sender] > _value);                             // Check If The Sender Has Enough Balance
        balanceOf[msg.sender] -= _value;                                      // Subtract From The Sender
        totalSupply -= _value;                                                // Updates TotalSupply
        remaining -= _value;                                                  // Update Remaining Tokens
        Burn(msg.sender, _value);                                             // Raise Event
        return true;
    }

function burnFrom(address _from, uint256 _value) public returns (bool success) // ERC20 Function Implementation Of Burn From
    {
        require(balanceOf[_from] >= _value);                                  // Check If The Target Has Enough Balance
        require(_value <= allowance[_from][msg.sender]);                      // Check Allowance
        balanceOf[_from] -= _value;                                           // Subtract From The Targeted Balance
        allowance[_from][msg.sender] -= _value;                               // Subtract From The Sender's Allowance
        totalSupply -= _value;                                                // Update TotalSupply
        remaining -= _value;                                                  // Update Remaining
        Burn(_from, _value);
        return true;
    }
} //  ECP Smart Contract End
