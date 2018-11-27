/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/10 11:04:41 by amaindro          #+#    #+#             */
/*   Updated: 2015/12/15 10:46:26 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list	*lst2;
	t_list	*tmp;

	if (!lst)
		return (NULL);
	if ((lst2 = ft_lstnew(lst->content, lst->content_size)) == NULL)
		return (NULL);
	lst2 = (f)(lst);
	tmp = lst2;
	while (lst->next != NULL)
	{
		lst2->next = (f)(lst->next);
		lst = lst->next;
		lst2 = lst2->next;
	}
	return (tmp);
}
