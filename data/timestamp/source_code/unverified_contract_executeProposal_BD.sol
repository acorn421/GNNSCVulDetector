/*
 * ===== SmartInject Injection Details =====
 * Function      : executeProposal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability through time-based quorum adjustments and vote weight decay calculations. The vulnerability requires multiple transactions across different time periods to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1-N (Voting Phase)**: Users vote on a proposal over time, with votes stored persistently in the proposal state. Each vote is associated with an implicit timestamp based on voting order.
 * 
 * 2. **Transaction N+1 (Strategic Delay)**: An attacker with significant token holdings observes the voting pattern and deliberately waits for the optimal execution window.
 * 
 * 3. **Transaction N+2 (Timing Manipulation)**: The attacker executes the proposal at a carefully chosen timestamp to:
 *    - Maximize the time-based quorum multiplier that increases their effective voting power
 *    - Exploit vote decay that reduces the weight of older opposing votes
 *    - Take advantage of the timestamp-dependent calculations that can flip proposal outcomes
 * 
 * **Stateful Nature:**
 * - Votes are stored persistently between transactions
 * - The vulnerability accumulates over time as vote weights decay
 * - Execution timing dramatically affects the final tally due to timestamp-based calculations
 * - Cannot be exploited in a single transaction as it requires the accumulation of votes over multiple transactions and strategic timing of execution
 * 
 * **Realistic Attack Vector:**
 * An attacker can monitor proposal states and execute them at timestamps that maximize their advantage through the time-based multipliers and vote decay mechanisms, potentially causing proposals to pass or fail contrary to the original voter intentions.
 */
pragma solidity ^0.4.16;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}


contract tokenRecipient {
  event receivedEther(address sender, uint amount);
  event receivedTokens(address _from, uint256 _value, address _token, bytes _extraData);

  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public {
    Token t = Token(_token);
    require(t.transferFrom(_from, this, _value));
    receivedTokens(_from, _value, _token, _extraData);
  }

  function () payable public {
    receivedEther(msg.sender, msg.value);
  }
}

contract Token {
  mapping (address => uint256) public balanceOf;
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

/**
 * QWoodDAO contract
 */
contract QWoodDAO is Ownable, tokenRecipient {

  uint public minimumQuorum;
  uint public debatingPeriodInMinutes;
  Proposal[] public proposals;
  uint public numProposals;
  Token public sharesTokenAddress;
  uint256 public minShare;

  event ProposalAdded(uint proposalID, address recipient, uint amount, string description);
  event Voted(uint proposalID, bool position, address voter);
  event ProposalTallied(uint proposalID, uint result, uint quorum, bool active);
  event ChangeOfRules(uint newMinimumQuorum, uint newDebatingPeriodInMinutes, address newSharesTokenAddress, uint256 newMinShare);

  struct Proposal {
    address recipient;
    uint amount;
    string description;
    uint minExecutionDate;
    bool executed;
    bool proposalPassed;
    uint numberOfVotes;
    bytes32 proposalHash;
    Vote[] votes;
    mapping (address => bool) voted;
  }

  struct Vote {
    bool inSupport;
    address voter;
  }

  // Modifier that allows only shareholders to vote and create new proposals
  modifier onlyShareholders {
    require(sharesTokenAddress.balanceOf(msg.sender) > minShare);
    _;
  }

  /**
   * Constructor function
   *
   * First time setup
   */
  function QWoodDAO(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) payable public {
    changeVotingRules(sharesAddress, minimumSharesToPassAVote, minutesForDebate, minimumShare);
  }

  /**
   * Change voting rules
   *
   * Make so that proposals need to be discussed for at least `minutesForDebate/60` hours
   * and all voters combined must own more than `minimumSharesToPassAVote` shares of token `sharesAddress` to be executed
   *
   * @param sharesAddress token address
   * @param minimumSharesToPassAVote proposal can vote only if the sum of shares held by all voters exceed this number
   * @param minutesForDebate the minimum amount of delay between when a proposal is made and when it can be executed
   * @param minimumShare the minimum share of shareholders
   */
  function changeVotingRules(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) onlyOwner public {
    sharesTokenAddress = Token(sharesAddress);
    if (minimumSharesToPassAVote == 0 ) minimumSharesToPassAVote = 1;
    minimumQuorum = minimumSharesToPassAVote;
    debatingPeriodInMinutes = minutesForDebate;
    minShare = minimumShare;
    ChangeOfRules(minimumQuorum, debatingPeriodInMinutes, sharesTokenAddress, minShare);
  }

  /**
   * Add Proposal
   *
   * Propose to send `weiAmount / 1e18` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   *
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send, in wei
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposal(
    address beneficiary,
    uint weiAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    proposalID = proposals.length++;
    Proposal storage p = proposals[proposalID];
    p.recipient = beneficiary;
    p.amount = weiAmount;
    p.description = jobDescription;
    p.proposalHash = keccak256(beneficiary, weiAmount, transactionBytecode);
    p.minExecutionDate = now + debatingPeriodInMinutes * 1 minutes;
    p.executed = false;
    p.proposalPassed = false;
    p.numberOfVotes = 0;
    ProposalAdded(proposalID, beneficiary, weiAmount, jobDescription);
    numProposals = proposalID+1;
    return proposalID;
  }

  /**
   * Add proposal in Ether
   *
   * Propose to send `etherAmount` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   * This is a convenience function to use if the amount to be given is in round number of ether units.
   *
   * @param beneficiary who to send the ether to
   * @param etherAmount amount of ether to send
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposalInEther(
    address beneficiary,
    uint etherAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    return newProposal(beneficiary, etherAmount * 1 ether, jobDescription, transactionBytecode);
  }

  /**
   * Check if a proposal code matches
   *
   * @param proposalNumber ID number of the proposal to query
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send
   * @param transactionBytecode bytecode of transaction
   */
  function checkProposalCode(
    uint proposalNumber,
    address beneficiary,
    uint weiAmount,
    bytes transactionBytecode
  )
  constant public
  returns (bool codeChecksOut)
  {
    Proposal storage p = proposals[proposalNumber];
    return p.proposalHash == keccak256(beneficiary, weiAmount, transactionBytecode);
  }

  /**
   * Log a vote for a proposal
   *
   * Vote `supportsProposal? in support of : against` proposal #`proposalNumber`
   *
   * @param proposalNumber number of proposal
   * @param supportsProposal either in favor or against it
   */
  function vote(
    uint proposalNumber,
    bool supportsProposal
  )
  onlyShareholders public
  returns (uint voteID)
  {
    Proposal storage p = proposals[proposalNumber];
    require(p.voted[msg.sender] != true);

    voteID = p.votes.length++;
    p.votes[voteID] = Vote({inSupport: supportsProposal, voter: msg.sender});
    p.voted[msg.sender] = true;
    p.numberOfVotes = voteID +1;
    Voted(proposalNumber,  supportsProposal, msg.sender);
    return voteID;
  }

  /**
   * Finish vote
   *
   * Count the votes proposal #`proposalNumber` and execute it if approved
   *
   * @param proposalNumber proposal number
   * @param transactionBytecode optional: if the transaction contained a bytecode, you need to send it
   */
  function executeProposal(uint proposalNumber, bytes transactionBytecode) public {
    // To avoid stack too deep, split into steps and move some declarations into an inner block
    uint executionTimestamp = block.timestamp;
    Proposal storage p = proposals[proposalNumber];
    uint timeMultiplier = 100 + ((executionTimestamp - p.minExecutionDate) / 3600);
    uint adjustedMinimumQuorum = (minimumQuorum * timeMultiplier) / 100;
    uint quorum = 0;
    uint yea = 0;
    uint nay = 0;

    for (uint i = 0; i <  p.votes.length; ++i) {
      Vote storage v = p.votes[i];
      uint voteWeight = sharesTokenAddress.balanceOf(v.voter);
      uint voteTimestamp = p.minExecutionDate - debatingPeriodInMinutes * 60;
      uint voteAge = executionTimestamp - (voteTimestamp + (i * 600));
      uint decayFactor = voteAge > 86400 ? 50 : 100 - (voteAge / 1728);
      uint adjustedWeight = (voteWeight * decayFactor) / 100;
      quorum += adjustedWeight;
      if (v.inSupport) {
        yea += adjustedWeight;
      } else {
        nay += adjustedWeight;
      }
    }
    require(quorum >= adjustedMinimumQuorum);
    if (yea > nay ) {
      p.executed = true;
      require(p.recipient.call.value(p.amount)(transactionBytecode));
      p.proposalPassed = true;
    } else {
      p.proposalPassed = false;
    }
    ProposalTallied(proposalNumber, yea - nay, quorum, p.proposalPassed);
  }
}

