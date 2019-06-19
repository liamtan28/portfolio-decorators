
# Authorization decorators for Express Controllers: an in depth look

## Liam Tan

Express offers the modern JS developer a lot of out of the box utility when developing web services. The Express router is a powerful tool for handling requests, triggering additional actions through middleware, and error handling, however there are some areas where Express leaves a lot to be desired. One unfortunate bi-product of Express' global middleware routing pattern is a tangible lack of granular access control over resources throughout your API. Recently, I have fallen in love with a new way to implement an authorization layer with any with as much specificity as you need. Combined from a solid Route-Controller-Service design pattern that I talk about extensively [here], decorator functions go a long way into solving this problem.

Decorators are nothing new. In fact, you have the tried and true “Design Patterns: Elements of Reusable Object-Oriented Software (1994)” to thank for the first formal introduction of the decorator design pattern. While other strictly Object Oriented Programming languages such as Java picked up decorators along the way, TypeScript has only recently answered the call for us JS devs, and now we even have a [Stage 2 proposal for native decorator support](https://github.com/tc39/proposal-decorators) in the works.

If you need a quick refresher, decorator functions are an implementation of the decorator pattern, which aims to add additional functionality to a preexisting method, without interfering with its original function. The most widely accepted method of doing this is by performing some action before the original method, with access to it’s arguments. In the current iteration of TypeScript, this looks something like this:
```
const WarnDrinker = (): Function => (target: any, property: any, descriptor: any): void => {
	console.log('Coming in hot!');
}

class Teapot {
	@WarnDrinker
	public pourTea(): void {
		//  Mmm tea!
	}
}  
```

In the above example, we declare a decorator function as a curried arrow function. The arguments provided to the implicitly returned function give us access to various bits of metadata about the function we are decorating. In this simple example, you can see that we could use decorators to do something as simple as log to our console, before the method is executed. 

One very useful thing we can do we decorators is preventing the decorated method from executing if certain conditions are not met. Below is a simple example of how you might go about this:

```
const PreventPourIfTooHot = (maximumTemp: number): Function => (target: any, property: any, descriptor: any): void => {
	//  Store a reference to the decorated method
	const pourTeaMethod: any = descriptor.value;
	//  Redeclare the value of the decorated method to only
	//  resolve if the appropriate conditions are met.
	descriptor.value = (function(...args): any {
		const [ teaTemp ] = args;
		if(teaTemp > maximumTemp) {
			throw {
				code: 814,
				message: "The server refuses to pour tea to hot!"
			}
		}
		return pourTeaMethod.call(this, ...args);
	});
}

class Teapot {
	@PreventPourIfTooHot(70);
	public pourTea(teaTemp: number): void {
		//  Mmm tea!
	}
}  
```

There is a lot more going on in this example. Firstly, you might've noticed that in addition to the decorated methods metadata, we can pass our own arguments into the decorator function. In this case, we are supplying the decorator with the maximum temperature the tea can be at if we want to proceed with pouring. We do this by redefining the decorated method to have additional logic before the original function is called. An important distinction should be made here: **the decorated method is executed regardless, but instead is modified to include additional logic**. We can use this, as we have in the above example, to first throw an error, or something else. 

Now that you're up to speed, you might want to take the time to go make a cup of tea, because we are about to implement a neat authorization decorator function that you can use to protect actions throughout your web services.

Consider the following actions on a controller:

```
	 class SchoolController extends BaseController {
		
		private schoolService: SchoolService;
		public constructor() {
			this.schoolService = new SchoolService();
		}
		//  Accessible by anyone successfully authenticated
		@Protected()
		public readAction(req: Request, res: Response, next: NextFunction): void {
			return this.schoolService.getSchools();
		}
		//  Accessible with anyone with role ORG_USER OR SCHOOL_USER
		@Protected([ERole.ORG_USER, ERole.SCHOOL_USER])
		public updateAction(req: Request, res: Response, next: NextFunction): void {
			return this.schoolService.updateSchool(req.params.id, req.body);
		}
		//  Accessible to only ORG_ADMINS
		@Protected(ORG_ADMIN)
		public deleteAction(req: Request, res: Response, next: NextFunction): void {
			return this.schoolService.deleteSchool(req.params.id);
		}
	}
```
Above are three demo actions, each with it's own level of granular access control. The code is very readable, the logic behind authorization totally obfuscated, and a high level of control can be provided to each action. Let's take a deep dive into how we might go about implementing the above decorator functions (spoiler alert, we are going to restrict access in the same way we did the scalding hot tea):

Let's begin by setting up our decorator function like before.

```
//  ...
declare  enum  ERole {
	STUDENT  =  'student',
	SCHOOL  =  'school',
	ORG  =  'organisation',
}
//  ...
export  const  Protected  = (roles?:  ERole  |  ERole[]):  Function  => (target:  any, property:  any, descriptor:  any):  void  => {

	const  decoratedMethod: (request:  Request, response:  Response, next:  NextFunction) =>  any  =  descriptor.value;
	descriptor.value = (function(...args) {
		
		const  request:  Request  =  args[0];

		// If the decorator function doesn't wrap a controller action with a request arg, we cannot verify
		if(!(request  instanceof  Request)) {
			throw  new  InternalServerError('Invalid controller action passed into Protected decorator function');
		}
		//  ...
```

We begin by first validating that the developer (you!) have decorated an appropriate function. In this context, we require the decorated method to be a controller action, with it's first argument being Express' `Request` class. In the event that this isn't the case, an error is raised with an appropriate message (**note** *if you're at all interested in the particular global error handling pattern used in the above example to raise custom errors, and handle async functions, see my article [here]*).

We can further typecheck the additional arguments passed into the actual decorator function (in this instance, the required roles) to ensure that we can proceed:

```
// The roles passed to the decorator must be either:
// 1. an Array (which can be empty)
// 2. a string (hopefully of type ERole) with a length
// 3. undefined
// If they are none of the above, internal server error should be raised.

if(
	roles  !==  undefined  &&
	!(roles  instanceof  Array) &&
	(
		typeof  roles  !==  "string"  ||
		typeof  roles  ===  "string"  &&
		roles.length ===  0
	)
) {
	throw  new  InternalServerError('Invalid argument passed to Protected decorator function');
}
```
For this example, the I am going to use the JWT token provided by [AWS Cognito](https://aws.amazon.com/cognito/) to manage the users role (**note** *I happen to have used Cognito here, but you may use the exact same strategy for any JWT based auth implementation*). Assuming that the user has the encoded token attached to their request payload, and the Cognito User Pool allows for a custom attribute called `custom:role`, this will be implemented as follows: 

```
//  ...
const  JWT_SECRET:  string  =  '********************';
declare  interface  ICognitoJWTTokenDecoded {
	"custom:role":  ERole;
}
//  ...
const  tokenEncoded:  string  =  request.headers.Authorization.split('Bearer')[1];

// Verify the token. If tokenEncoded happens to be missing, we would treat the request as Unauthorized regardless. However
// there is a slight computational and latency advantage to returning early if none was present.
if(!tokenEncoded || typeof tokenEncoded !== 'string') {
	throw new UnauthorizedError();
}
// proceed to verify and then base64 decode token data. If the data is not present, or a payload on the token
// does not include the role property, we can throw an Unauthoized error appropriately.
const  tokenDecoded: ICognitoJWTTokenDecoded  =  jwt.verify(JWT_SECRET, tokenEncoded.trim());
if(!tokenDecoded['custom:role']) {
	throw  new  UnauthorizedError();
}
// If no roles were passed to the function, move on, as token is verified.
if(roles === undefined | (roles instanceof Array && roles.length === 0)) {
	return decoratedMethod.call(this, ...args);
}
```

Here we see the extraction of the encoded token, as well as the verification that the token is valid. If there were no required roles for this decorator, or an empty array was passed in, we can proceed with the decorated method as per usual. Let's finish off this strategy with some logic to handle any roles passed into the decorator:

```
// convert into array where necessary and check if the decoded role is contained in the role args
if(!(roles  instanceof  Array)) {
	roles  = [ roles ];
}
// This particular role based access control strategy treats roles passed into the decorator as OR logical, meaning
// the user will only have one role, and they are considered permitted if they have any of the roles included.
// Javascript's "includes" algorithm is notoriously slow, and looking at it's polyfill it appears to be worst case
// O(n), but the number of roles being searched is theoretically low.
if(!roles.includes(tokenDecoded['custom:role'])) {
	throw  new  ForbiddenError();
}
// proceed with function where appropriate
return  decoratedMethod.call(this, ...args);
```

We begin by converting the argument into an array when necessary. With this, we are able to iterate over the roles permitted with the role provided by the users JWT token, and either forbid or allow access to the decorated function based on the result.

And that's all she wrote! I have comfortably even this simple implementation in production systems, scaling and supporting many thousands of users. The clarity of code, especially once obfuscated and implemented across all of your controllers offers immense value over the lifespan of your project.

![Protected Decorator in a production system](https://picasaweb.google.com/104704203622968957824/6704220352185573281#6704220350619225730 "Protected Decorator in a production system")
 
This is a simple solution most applicable when your application only calls for broad access control, with relatively static roles associated with users, however in larger scale applications, the need for more granular control might be necessary. Enter: HRBAC (Hierarchical Role Based Access Control).

![Simple HRBAC diagram](https://picasaweb.google.com/104704203622968957824/6704221871747950785#6704221875668680226)

The core concept of HRBAC is that roles associated with a user don't dictate directly what they have control over. Rather, each role is comprised of several *scopes*, which allow granular control over resources. Finally, scopes are *hierarchical*, meaning that some scopes can be comprised of others, granting access to large areas of resources. Let's begin with a really simple conceptual hierarchy of our application's scopes:

![Poorly drawn Hierarchy](https://lh3.googleusercontent.com/ni9oTpbFYY2hqrrKDQwDjHWsn1DcNOc8WP7leE--40_ehDS1oyWaB5_y4HDNmAN_I1a3i4CP4d_J)

Consider the above poorly drawn conceptual tree: we can see that some *scopes* encompass others (roles with the `ORG_WRITE` scope inherently have the `ORG_WRITE_SELF`, and `ORG_WRITE_OTHER` scopes). As an example, a school admin might have the scope `SCHOOL_ALL`, giving them access to any scope beneath the node. 

Looking at the above tree, it bears a striking resemblence to our best friend: the **binary search tree**. A few caveats and assumptions are being made, so before I proceed to implement HRBAC in decorator form, condsider the following:

 1. There are certainly less verbose, more naive solutions to implement the following, however when systems require granular scopes in the hundreds or thousands, some significant performance considerations should be made. It is important to remember that adding a new domain of functionality introduces potentially dozens of new scopes.
 2. I have conveniently created a conceptual tree that is out-of-the-box balanced and binary, so more complex hierarchies might require ternary or n/k-ary trees, or somewhere in-between. It is worth considering that introducing new scopes will change the balance and ordering of the tree, forcing you to re-assess your implementation. 

All that being said, the majority of the code below will stay the same if you opt for a more naive solution. Let's begin!

![Poorly drawn BinTree](https://lh3.googleusercontent.com/P9k6XdSrDFsEsWvQ6E_JhCkBY2nHAO1PG1SR_knd9kGx_D6etGv-lDCmKsZIq-6HQWM6MWDR7bEM)

Above I have simply ordered the conceptual hierarchy into a balanced binary tree with numerical values. This will ensure our ability to traverse the tree in our implementation below:
```
// Standard balanced binary tree implementation. Only stores data, no generic traversal methods.
// Stores generic value T as value type.

class  TreeNode<T> {
	value:  T;
	left:  TreeNode<T>;
	right:  TreeNode<T>;
	
	constructor(value:  T, left?:  TreeNode<T>, right?:  TreeNode<T>) {
		this.value =  value;
		this.left =  left;
		this.right =  right;
	}
}

class  BinTree<T> {
	root:  TreeNode<T>;
	constructor(root:  TreeNode<T>) {
		this.root  = root;
	}
}

// Implemented Binary tree, to store heirarchical information of scopes. Has custom traversal method
// that returns the target node value, and the parent node values.
class  HRBACBinTree  extends  BinTree<EScope> {
	constructor(root:  TreeNode<EScope>) {
		super(root);
	}

	findAllParentScopes(target:  EScope) {
		let  node:  TreeNode<EScope> =  this.root;
		const  parentScopes:  EScope[] = [target];
		while(true) {
			
			if(node  ===  undefined  ||  node.value ===  target) {
				break;
			}

			parentScopes.push(node.value);
			if(target  <  node.value) {
				node  =  node.left;
			}
			else  if(target  >  node.value) {
				node  =  node.right;
			}
		}

		return  parentScopes;
	}
}

// Postorder array of scopes, with a numerical value. These are to be mapped to an instance
// of HRBACBinTree
enum  EScope {
	ORG_READ_SELF  =  0,
	ORG_READ_ALL  =  1,
	ORG_READ_OTHER  =  2,
	ORG_ALL  =  3,
	ORG_WRITE_SELF  =  4,
	ORG_WRITE_ALL  =  5,
	ORG_WRITE_OTHER  =  6,
	ALL  =  7,
	SCHOOL_READ_SELF  =  8,
	SCHOOL_READ_ALL  =  9,
	SCHOOL_READ_OTHER  =  10,
	SCHOOL_ALL  =  11,
	SCHOOL_WRITE_SELF  =  12,
	SCHOOL_WRITE_ALL  =  13,
	SCHOOL_WRITE_OTHER  =  14,
}
// The implementation of HRBACBinTree, with the appropriate heirarchical mapping.
const  HRBAC_BINTREE:  HRBACBinTree  =  new  HRBACBinTree(
	new  TreeNode(EScope.ALL,
		new  TreeNode(EScope.ORG_ALL,
			new  TreeNode(EScope.ORG_READ_ALL,
				new  TreeNode(EScope.ORG_READ_SELF),
				new  TreeNode(EScope.ORG_READ_OTHER),
			),
			new  TreeNode(EScope.ORG_WRITE_ALL,
				new  TreeNode(EScope.ORG_WRITE_SELF),
				new  TreeNode(EScope.ORG_WRITE_OTHER),
			),
		),
		new  TreeNode(EScope.SCHOOL_ALL,
			new  TreeNode(EScope.SCHOOL_READ_ALL,
				new  TreeNode(EScope.SCHOOL_READ_SELF),
				new  TreeNode(EScope.SCHOOL_READ_OTHER),
			),
			new  TreeNode(EScope.SCHOOL_WRITE_ALL,
				new  TreeNode(EScope.SCHOOL_WRITE_SELF),
				new  TreeNode(EScope.SCHOOL_WRITE_OTHER),
			),
		),
	),
);
declare  interface  IRole {
	name:  string;
	scopes:  EScope[];
}

// Some dummy roles, containing scopes. This information would typically come from a relational store.
const  USER_ROLES:  IRole[] = [
	{
		name: 'GOD_USER',
		scopes: [EScope.ALL],
	},
	{
		name: 'SCHOOL_ADMIN',
		scopes: [EScope.SCHOOL_ALL],
	},	
	{
		name: 'ORG_STAFF',
		scopes: [EScope.ORG_WRITE_SELF, EScope.ALL],
	}
];
```
If you're anything like me, you're bored to death of writing/looking at implementations of binary trees. Now we are all set up to consume the hierarchy in a helper function below:

```
// Helper function for determining resource access based on a user's role, and the required scopes.
// Uses a BinTree implementation for scopes in order to find all permitted scopes.

const  determineResourceAccessByScopes  = (requiredScopes:  EScope[], userRole:  IRole):  boolean  => {
	
	// Using the BinTree implementation above, map all required scopes to instead be the superset of all scopes
	// that have heirachical access to the resource.
	const  requiredParentScopes:  any[] =  requiredScopes.map((scope:  EScope) =>  HRBAC_BINTREE.findAllParentScopes(scope));
	
		let  permitted:  boolean  =  true;
		// Iterating over each superset for each of the required scopes, find the intersection between the role's scopes
		// and the superset. If the length of the intersect is 0 (there is none), restrict the users access.
		for(let  scopes  of  requiredParentScopes) {

			const  includedScopes:  EScope[] =  scopes.filter((scope:  EScope) =>  userRole.scopes.includes(scope));
			permitted  =  permitted  &&  includedScopes.length >  0;
		}	
	return  permitted;
}
```

Quite simply, using the traversal method we wrote for our hierarchy, the method determines all parent scopes of a set of required scopes, and check's the user's role for those scopes. Dropping this into the end of our decorator function, we complete the loop:

```
// ...

// Implement resource access helper function declared above. If the result is false, throw.
if(!determineResourceAccessByScopes(requiredScopes, userRole)) {
	throw  new  ForbiddenError();
}
// proceed with function where appropriate
return  decoratedMethod.call(this, ...args);

// ...
```
And you're done! You now have a decorator function that can be used for granular access control, and with all the nitty gritty logic obfuscated, can be consumed across your application with a high level of clarity.

Decorators are awesome. You can find endless places to make use of them. When stacking decorators, a great level of clarity about the synchronous procedures happening before your method can be achieved. Mimicking the above implementation, take a quick look at how we can continue to stack decorators to not just authorize a user, but validate their payload:

![Stacking decorators](https://picasaweb.google.com/104704203622968957824/6704229514801097281#6704229515663680130) 

If that was TMI, only take the bits you need. The idea of decorators is to unencumbered you, so if you ever feel like they are having the adverse effect, maybe reconsider your implementation. I've made all of the above code available in a repo you can find [here]. Go brew another cup of tea, and give implementing your auth layer in decorator format!



